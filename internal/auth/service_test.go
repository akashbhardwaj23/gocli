package auth

import (
	"testing"

	"github.com/akashbhardwaj23/cli-auth/internal/models"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func testService(t *testing.T) *Service {

	t.Helper()

	database, err := gorm.Open(
		sqlite.Open(":memory:"),
		&gorm.Config{},
	)

	require.NoError(t, err)

	err = database.AutoMigrate(
		&models.User{},
	)

	require.NoError(t, err)

	t.Cleanup(func() {
		sqlDB, err := database.DB()

		if err == nil {
			sqlDB.Close()
		}
	})

	return NewService(
		database,
		Config{
			LockOutThreshold: 3,
			LocOutMinutes:    15,
			SeesionTimeOut:   30,
		},
	)
}

func TestRegisterAndLogin(t *testing.T) {

	service := testService(t)

	err := service.Register(
		"user",
		"correct-password",
	)

	require.NoError(t, err)

	user, err := service.Login(
		"user",
		"correct-password",
		"",
	)

	require.NoError(t, err)
	require.Equal(
		t,
		"user",
		user.Username,
	)
}

func TestDuplicateUser(t *testing.T) {

	service := testService(t)

	err := service.Register(
		"user",
		"correct-password",
	)

	require.NoError(t, err)

	err = service.Register(
		"user",
		"another-password",
	)

	require.Error(t, err)
}

func TestInvalidPassword(t *testing.T) {

	service := testService(t)

	err := service.Register(
		"user",
		"correct-password",
	)

	require.NoError(t, err)

	_, err = service.Login(
		"user",
		"wrong-password",
		"",
	)

	require.Error(
		t,
		err,
		ErrInvalidCredentials,
	)
}

func TestAccountLockout(t *testing.T) {

	service := testService(t)

	err := service.Register(
		"user",
		"correct-password",
	)

	require.NoError(t, err)

	for i := 0; i < 3; i++ {

		_, _ = service.Login(
			"user",
			"wrong-password",
			"",
		)
	}

	_, err = service.Login(
		"user",
		"correct-password",
		"",
	)

	require.Error(
		t,
		err,
		ErrAccountLocked,
	)
}

func TestEnableAndDisableMFA(t *testing.T) {

	service := testService(t)

	err := service.Register(
		"user",
		"correct-password",
	)

	require.NoError(t, err)

	secret, err := service.EnableMFA(
		"user",
	)

	require.NoError(t, err)
	require.NotEmpty(t, secret)

	user, err := service.GetUser("user")

	require.NoError(t, err)
	require.True(t, user.MFAEnabled)
	require.NotNil(t, user.TOTPSecret)

	err = service.DisableMFA("user")

	require.NoError(t, err)

	user, err = service.GetUser("user")

	require.NoError(t, err)
	require.False(t, user.MFAEnabled)
	require.Nil(t, user.TOTPSecret)
}
