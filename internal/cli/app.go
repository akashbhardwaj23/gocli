package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/akashbhardwaj23/cli-auth/internal/auth"
	"github.com/akashbhardwaj23/cli-auth/internal/models"
	"github.com/akashbhardwaj23/cli-auth/internal/session"

	"github.com/chzyer/readline"
	"golang.org/x/term"
)

type App struct {
	auth     *auth.Service
	sessions *session.Manager
	current  session.Session
}

func NewApp(
	authService *auth.Service,
	sessionManager *session.Manager,
) *App {

	return &App{
		auth:     authService,
		sessions: sessionManager,
	}
}

func (a *App) Run() {

	fmt.Println("================================")
	fmt.Println("       Secure CLI Login")
	fmt.Println("================================")
	fmt.Println("Type 'help' for available commands.")
	fmt.Println()

	rl, err := readline.NewEx(
		&readline.Config{
			Prompt:          "gocli> ",
			HistoryFile:     ".cli_login_history",
			InterruptPrompt: "^C",
			EOFPrompt:       "exit",

			AutoComplete: readline.NewPrefixCompleter(
				readline.PcItem("register"),
				readline.PcItem("login"),
				readline.PcItem("help"),
				readline.PcItem("whoami"),
				readline.PcItem("enable-2fa"),
				readline.PcItem("disable-2fa"),
				readline.PcItem("logout"),
				readline.PcItem("exit"),
			),
		},
	)

	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"failed to initialize CLI:",
			err,
		)

		return
	}

	defer rl.Close()

	for {

		if a.isLoggedIn() {

			rl.SetPrompt(
				fmt.Sprintf(
					"%s> ",
					a.current.User.Username,
				),
			)

		} else {

			rl.SetPrompt("gocli> ")
		}

		line, err := rl.Readline()

		if err != nil {
			fmt.Println()
			return
		}

		command := strings.TrimSpace(line)

		if command == "" {
			continue
		}

		a.execute(command)
	}
}

func (a *App) execute(input string) {

	parts := strings.Fields(input)

	if len(parts) == 0 {
		return
	}

	command := strings.ToLower(parts[0])

	switch command {

	case "register":
		a.register()

	case "login":
		a.login()

	case "whoami":
		a.whoami()

	case "enable-2fa":
		a.enable2FA()

	case "disable-2fa":
		a.disable2FA()

	case "logout":
		a.logout()

	case "help":
		a.help()

	case "exit":
		a.logout()
		fmt.Println("Goodbye!")
		os.Exit(0)

	default:
		fmt.Printf(
			"Unknown command: %s\n",
			command,
		)

		fmt.Println(
			"Type 'help' for available commands.",
		)
	}
}

func (a *App) help() {

	fmt.Println()

	if a.isLoggedIn() {

		fmt.Println("Available commands:")
		fmt.Println()
		fmt.Println("  whoami        Show current user details")
		fmt.Println("  enable-2fa    Enable TOTP two-factor authentication")
		fmt.Println("  disable-2fa   Disable two-factor authentication")
		fmt.Println("  logout        End current session")
		fmt.Println("  help          Show available commands")
		fmt.Println("  exit          Exit application")

	} else {

		fmt.Println("Available commands:")
		fmt.Println()
		fmt.Println("  register      Create a new user")
		fmt.Println("  login         Login")
		fmt.Println("  help          Show available commands")
		fmt.Println("  exit          Exit application")
	}

	fmt.Println()
}

func readInput(prompt string) string {

	fmt.Print(prompt)

	reader := bufio.NewReader(os.Stdin)

	value, _ := reader.ReadString('\n')

	return strings.TrimSpace(value)
}

func readPassword(prompt string) string {

	fmt.Print(prompt)

	password, err := term.ReadPassword(
		int(os.Stdin.Fd()),
	)

	fmt.Println()

	if err != nil {
		return ""
	}

	return string(password)
}

func (a *App) register() {

	fmt.Println()
	fmt.Println("========== Register ==========")

	username := readInput("Username: ")

	password := readPassword(
		"Password: ",
	)

	confirmation := readPassword(
		"Confirm password: ",
	)

	if password != confirmation {

		fmt.Println(
			"Error: passwords do not match.",
		)

		return
	}

	err := a.auth.Register(
		username,
		password,
	)

	if err != nil {

		fmt.Println(
			"Registration failed:",
			err,
		)

		return
	}

	fmt.Println()
	fmt.Println(
		"Registration successful.",
	)
}

func (a *App) login() {

	if a.isLoggedIn() {

		fmt.Println(
			"You are already logged in.",
		)

		return
	}

	fmt.Println()
	fmt.Println("============ Login ============")

	username := readInput("Username: ")

	password := readPassword(
		"Password: ",
	)

	var totpCode string

	// We need to know whether the user has MFA enabled
	// before asking for the TOTP code.
	user, err := a.auth.GetUser(username)

	if err == nil && user.MFAEnabled {

		totpCode = readInput(
			"2FA code: ",
		)
	}

	user, err = a.auth.Login(
		username,
		password,
		totpCode,
	)

	if err != nil {

		fmt.Println(
			"Login failed:",
			err,
		)

		return
	}

	newSession, err :=
		a.sessions.Create(user)

	if err != nil {

		fmt.Println(
			"Unable to create session:",
			err,
		)

		return
	}

	a.current = newSession

	fmt.Println()
	fmt.Println("Login successful.")

	a.printUser(
		user,
		newSession.ExpiresAt,
	)
}

func (a *App) whoami() {

	if !a.isLoggedIn() {

		fmt.Println(
			"Please login first.",
		)

		return
	}

	user, err := a.auth.GetUser(
		a.current.User.Username,
	)

	if err != nil {

		fmt.Println(
			"Unable to retrieve user details:",
			err,
		)

		return
	}

	a.printUser(
		user,
		a.current.ExpiresAt,
	)
}

func (a *App) printUser(
	user *models.User,
	expiresAt time.Time,
) {

	lastLogin := "Never"

	if user.LastLoginAt != nil {

		lastLogin =
			user.LastLoginAt.
				Local().
				Format(
					"2006-01-02 15:04:05",
				)
	}

	mfaStatus := "disabled"

	if user.MFAEnabled {
		mfaStatus = "enabled"
	}

	fmt.Println()
	fmt.Println("========== User Details ==========")

	fmt.Printf(
		"Username: %s\n",
		user.Username,
	)

	fmt.Printf(
		"Registration date: %s\n",
		user.RegisteredAt.
			Local().
			Format(
				"2006-01-02 15:04:05",
			),
	)

	fmt.Printf(
		"MFA status: %s\n",
		mfaStatus,
	)

	fmt.Printf(
		"Session expiration: %s\n",
		expiresAt.
			Local().
			Format(
				"2006-01-02 15:04:05",
			),
	)

	fmt.Printf(
		"Last login: %s\n",
		lastLogin,
	)

	fmt.Println(
		"==================================",
	)
	fmt.Println()
}

func (a *App) enable2FA() {

	if !a.isLoggedIn() {

		fmt.Println(
			"Please login first.",
		)

		return
	}

	if a.current.User.MFAEnabled {

		fmt.Println(
			"2FA is already enabled.",
		)

		return
	}

	secret, err :=
		a.auth.EnableMFA(
			a.current.User.Username,
		)

	if err != nil {

		fmt.Println(
			"Unable to enable 2FA:",
			err,
		)

		return
	}

	fmt.Println()
	fmt.Println(
		"2FA enabled successfully.",
	)

	fmt.Println()
	fmt.Println(
		"Add this secret to Google Authenticator:",
	)

	fmt.Println()
	fmt.Println(secret)
	fmt.Println()

	fmt.Println(
		"Your authenticator will generate",
		"a 6-digit code for future logins.",
	)

	// Refresh current user information.
	user, err := a.auth.GetUser(
		a.current.User.Username,
	)

	if err == nil {
		a.current.User = user
	}
}

func (a *App) disable2FA() {

	if !a.isLoggedIn() {

		fmt.Println(
			"Please login first.",
		)

		return
	}

	if !a.current.User.MFAEnabled {

		fmt.Println(
			"2FA is already disabled.",
		)

		return
	}

	confirmation := readInput(
		"Type DISABLE to confirm: ",
	)

	if confirmation != "DISABLE" {

		fmt.Println(
			"Operation cancelled.",
		)

		return
	}

	err := a.auth.DisableMFA(
		a.current.User.Username,
	)

	if err != nil {

		fmt.Println(
			"Unable to disable 2FA:",
			err,
		)

		return
	}

	fmt.Println(
		"2FA disabled successfully.",
	)

	user, err := a.auth.GetUser(
		a.current.User.Username,
	)

	if err == nil {
		a.current.User = user
	}
}

func (a *App) logout() {

	if a.current.Token != "" {

		a.sessions.Delete(
			a.current.Token,
		)
	}

	a.current = session.Session{}

	fmt.Println(
		"Logged out.",
	)
}

func (a *App) isLoggedIn() bool {

	if a.current.Token == "" {
		return false
	}

	_, ok := a.sessions.Get(
		a.current.Token,
	)

	if !ok {

		a.current = session.Session{}

		return false
	}

	return true
}
