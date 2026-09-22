package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/akashbhardwaj23/cli-auth/internal/models"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrInvalidCredentials = errors.New(
		"invalid username or password",
	)
	ErrUserExists = errors.New(
		"username already exists",
	)
	ErrUserNotFound = errors.New(
		"user not found",
	)

	ErrInvalidTOTP = errors.New(
		"invalid 2fa code",
	)

	ErrAccountLocked = errors.New(
		"account temporary locked",
	)
)

type Config struct {
	LockOutThreshold int
	LocOutMinutes    int
	SeesionTimeOut   int
}

type Service struct {
	db     gorm.DB
	config Config
}

func NewService(
	database *gorm.DB,
	config Config,
) *Service {
	return &Service{
		db:     *database,
		config: config,
	}
}

func (s *Service) Register(
	username string,
	password string,
) error {

	username = strings.TrimSpace(username)

	if len(username) < 3 ||
		len(username) > 32 {

		return errors.New(
			"username must be between 3 and 32 characters",
		)
	}

	if strings.ContainsAny(
		username,
		" \t\r\n",
	) {

		return errors.New(
			"username cannot contain whitespace",
		)
	}

	if len(password) < 8 {

		return errors.New(
			"password must be at least 8 characters",
		)
	}

	passwordHash, err :=
		bcrypt.GenerateFromPassword(
			[]byte(password),
			bcrypt.DefaultCost,
		)

	if err != nil {
		return err
	}

	user := models.User{
		Username:     username,
		PasswordHash: string(passwordHash),
	}

	err = s.db.Create(&user).Error

	if err != nil {

		if errors.Is(
			err,
			gorm.ErrDuplicatedKey,
		) {

			return ErrUserExists
		}

		// depending on GORM configuration.
		if strings.Contains(
			strings.ToLower(err.Error()),
			"unique",
		) {
			return ErrUserExists
		}

		return err
	}

	return nil
}

func (s *Service) recordFailure(
	user *models.User,
) {

	user.FailedAttempts++

	if user.FailedAttempts >=
		s.config.LockOutThreshold {

		lockUntil := time.Now().Add(
			time.Duration(
				s.config.LocOutMinutes,
			) * time.Minute,
		)

		user.FailedAttempts = 0

		user.LockedUntil = &lockUntil
	}

	_ = s.db.Save(user).Error
}

func (s *Service) GetUser(
	username string,
) (*models.User, error) {

	var user models.User

	err := s.db.
		Where("username = ?", username).
		First(&user).
		Error

	if err != nil {

		if errors.Is(
			err,
			gorm.ErrRecordNotFound,
		) {

			return nil, ErrUserNotFound
		}

		return nil, err
	}

	return &user, nil
}

func (s *Service) Login(
	username string,
	password string,
	totpCode string,
) (*models.User, error) {

	user, err := s.GetUser(username)

	if err != nil {
		return nil, ErrInvalidCredentials
	}

	now := time.Now()

	if user.LockedUntil != nil &&
		user.LockedUntil.After(now) {

		return nil, ErrAccountLocked
	}

	// Verify password.
	err = bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash),
		[]byte(password),
	)

	if err != nil {

		s.recordFailure(user)

		return nil, ErrInvalidCredentials
	}

	if user.MFAEnabled {

		if user.TOTPSecret == nil {

			return nil, errors.New(
				"2FA is enabled but secret is missing",
			)
		}

		valid := totp.Validate(
			totpCode,
			*user.TOTPSecret,
		)

		if !valid {

			s.recordFailure(user)

			return nil, ErrInvalidTOTP
		}
	}

	// Successful login.
	user.FailedAttempts = 0
	user.LockedUntil = nil

	user.LastLoginAt = &now

	err = s.db.Save(user).Error

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *Service) EnableMFA(
	username string,
) (string, error) {

	user, err := s.GetUser(username)

	if err != nil {
		return "", err
	}

	key, err := totp.Generate(
		totp.GenerateOpts{
			Issuer:      "CLI Login",
			AccountName: user.Username,
			SecretSize:  20,
		},
	)

	if err != nil {
		return "", err
	}

	secret := key.Secret()

	user.MFAEnabled = true
	user.TOTPSecret = &secret

	if err := s.db.Save(user).Error; err != nil {
		return "", err
	}

	return secret, nil
}

func (s *Service) DisableMFA(
	username string,
) error {

	user, err := s.GetUser(username)

	if err != nil {
		return err
	}

	user.MFAEnabled = false
	user.TOTPSecret = nil

	return s.db.Save(user).Error
}
