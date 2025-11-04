package main

// Library Package needed for aes, input scrypt, clearing clipboard, clean memory..
import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/atotto/clipboard"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// memory protection techniques

// securestring is a structure to hold passwords
type SecureString struct {
	data []byte
}

// it takes a password and converts it to a secure byte slice.
func NewSecureString(s string) *SecureString {
	ss := &SecureString{
		data: make([]byte, len(s)), //create a new byte slice same len of pass
	}
	copy(ss.data, []byte(s))
	lockMemory(ss.data) // prevent this memory from being swapped to disk
	return ss
}

// string representation of the data.
func (ss *SecureString) String() string {
	if ss.data == nil {
		return ""
	}
	return string(ss.data)
}

// return the underlying byte slice of dta which is used in cryptographic functions
func (ss *SecureString) Bytes() []byte {
	return ss.data
}

// wipe securely destroys the sensitive data stored
func (ss *SecureString) Wipe() {
	if ss.data == nil {
		return
	}

	// overwrite the memory multiple times with patterns
	for i := 0; i < 3; i++ {
		for j := range ss.data {
			ss.data[j] = 0
		}
		for j := range ss.data {
			ss.data[j] = 0xFF
		}
		rand.Read(ss.data)
	}
	// overwrite with zeros to leave the memory clean
	for j := range ss.data {
		ss.data[j] = 0
	}
	// unlock the memory allowing it to be swapped again.
	unlockMemory(ss.data)
	ss.data = nil
	runtime.GC() // force a garbage collection run to quickly reclaim the memory.
}

// lock memory to swap file on disk
func lockMemory(b []byte) {
	if len(b) == 0 {
		return
	}
	if runtime.GOOS == "windows" { // since testing is in cmd window we check the time in windows
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		virtualLock := kernel32.NewProc("VirtualLock")
		// call function invokes virtualLock with the address of the data and lock it from physical ram

		virtualLock.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	}
}

// oposite of lock, it unlock the memory allowing to add to it
func unlockMemory(b []byte) {
	if len(b) == 0 {
		return
	}
	if runtime.GOOS == "windows" {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		virtualUnlock := kernel32.NewProc("VirtualUnlock")
		virtualUnlock.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	}
}

// securely overwrites a  byte slice.
func secureWipeBytes(data []byte) {
	if len(data) == 0 {
		return
	}
	patterns := []byte{0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00} //a standard for disk data

	for _, pattern := range patterns {
		for i := range data {
			data[i] = pattern
		}
	}
	rand.Read(data) // overwrite with random data as a final pass

	for i := range data {
		data[i] = 0
	}
	runtime.KeepAlive(data) // by ensuring the 'data' variable is kept alive until this point.
}

// since Go strings are immutable, it cannot overwrite the underlying memory.
func secureWipeString(s *string) {
	if s == nil || *s == "" {
		return
	}
	// clear the pointer and force GC to quickly remove it of the memory.
	*s = ""
	runtime.GC()
}

// secureComparePasswords performs a comparison in constant time.
func secureComparePasswords(pass1, pass2 string) bool {
	return subtle.ConstantTimeCompare([]byte(pass1), []byte(pass2)) == 1
}

// DATA STRUCTURES

// PasswordEntry represents a single account consists: user name, password, note and website name
type PasswordEntry struct {
	Site     string `json:"site"` // website or servce name
	Username string `json:"username"`
	Password string `json:"password"`
	Notes    string `json:"notes"`
}

// securely clears all sensitive string fields in a PasswordEntr.
func (pe *PasswordEntry) Wipe() {
	secureWipeString(&pe.Password)
	secureWipeString(&pe.Username)
	secureWipeString(&pe.Site)
	secureWipeString(&pe.Notes)
}

// stores all account crediential in a list
type PasswordDatabase struct {
	Entries []PasswordEntry `json:"entries"`
}

// Wipe securely clears the entire database from memory.
func (db *PasswordDatabase) Wipe() {
	if db == nil || db.Entries == nil {
		return
	}
	for i := range db.Entries {
		db.Entries[i].Wipe() // call the Wipe() method on each individual entry to clear its contents.
	}
	db.Entries = nil
	runtime.GC()
}

// path of cloud and how if cloud syncronzition backup is activated or not
type CloudSyncConfig struct {
	Enabled   bool   // check if back is activated or not
	CloudPath string // path used to store the backup encrypted file.
}

// generate an encryption key using the scrypt algorithm.
func DeriveKey(masterPassword string, salt []byte) ([]byte, error) {
	const ( // parameters used for scrypt
		N      = 16384
		r      = 8
		p      = 1
		keyLen = 32
	)
	// performs the key derivation process.
	key, err := scrypt.Key([]byte(masterPassword), salt, N, r, p, keyLen)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// creates a cryptographically secure random salt which is used to protect against rainbow table attacks.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16) // salt of size 16 byte
	_, err := rand.Read(salt)
	return salt, err
}

// encrypt uses AES-256 GCM
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// create a new AES block cipher using the  key.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block) //Wrap the AES block cipher in GCM
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize()) //generate a randon nonce each password entry
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil) // generate ciphertext using nonce and plaintext
	return ciphertext, nil
}

// decrypt ciphertext generated and return the original plaintext.
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key) //get aes block from the key
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize() //extract the Nonce
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	// verifies the integrity of the data using GCM's authentication tag.
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// DATABASE OPERATIONS

// CreateDatabase initializes a new, empty password database and saves it to a file.
func CreateDatabase(masterPassword string, filepath string) error {
	salt, err := GenerateSalt() // It generates a new, unique salt for the database file.
	if err != nil {
		return err
	}
	// initialize an empty PasswordDatabase struct.
	db := &PasswordDatabase{
		Entries: []PasswordEntry{},
	}

	return SaveDatabase(db, masterPassword, filepath, salt)
}

// SaveDatabase encrypts  database and writes it to the specified file path.
func SaveDatabase(db *PasswordDatabase, masterPassword string, filepath string, salt []byte) error {
	jsonData, err := json.Marshal(db) //onvert the in-memory database struct into a JSON byte slice
	if err != nil {
		return err
	}
	//ensure the plaintext JSON data is cleared from memory
	defer secureWipeBytes(jsonData)

	key, err := DeriveKey(masterPassword, salt) // dervie the key
	if err != nil {
		return err
	}
	defer secureWipeBytes(key) //Ensure the derived encryption key is cleared from memory

	ciphertext, err := Encrypt(jsonData, key)
	if err != nil {
		return err
	}

	fileData := append(salt, ciphertext...) // save the ciphertext in the file
	return os.WriteFile(filepath, fileData, 0600)
}

// LoadDatabase reads the encrypted database file, decrypts it, and loads it into memory.
func LoadDatabase(masterPassword string, filepath string) (*PasswordDatabase, []byte, error) {
	fileData, err := os.ReadFile(filepath) //get the encrypted file
	if err != nil {
		return nil, nil, err
	}

	if len(fileData) < 16 { // check if file is corrupted
		return nil, nil, errors.New("invalid database file")
	}

	salt := fileData[:16]       // extract salt
	ciphertext := fileData[16:] // extract ciphertext

	key, err := DeriveKey(masterPassword, salt) //dervie the key
	if err != nil {
		return nil, nil, err
	}
	defer secureWipeBytes(key) // clean key from memory

	plaintext, err := Decrypt(ciphertext, key) //decrypt the database
	if err != nil {
		return nil, nil, errors.New("incorrect master password or corrupted database")
	}
	defer secureWipeBytes(plaintext) //clean from memory

	var db PasswordDatabase
	if err := json.Unmarshal(plaintext, &db); err != nil {
		return nil, nil, err
	}

	return &db, salt, nil
}

// database operation(add, update, delwte, retrieve)

// allow us to add new password to entry list
func (db *PasswordDatabase) AddEntry(site, username, password, notes string) {
	entry := PasswordEntry{
		Site:     site,
		Username: username,
		Password: password,
		Notes:    notes,
	}
	db.Entries = append(db.Entries, entry)
}

// allow us to retrieve a password from entry list that contains the four fields
func (db *PasswordDatabase) GetEntry(site string) (*PasswordEntry, error) {
	for i := range db.Entries {
		if db.Entries[i].Site == site {
			return &db.Entries[i], nil
		}
	}
	return nil, fmt.Errorf("entry not found: %s", site)
}

// allow us to update the content of entry like username, pass, notes
func (db *PasswordDatabase) UpdateEntry(site, username, password, notes string) error {
	for i := range db.Entries {
		if db.Entries[i].Site == site {
			secureWipeString(&db.Entries[i].Password)
			secureWipeString(&db.Entries[i].Username)

			db.Entries[i].Username = username
			db.Entries[i].Password = password
			db.Entries[i].Notes = notes
			return nil
		}
	}
	return fmt.Errorf("entry not found: %s", site)
}

// allow us to delete an old password from entry list
func (db *PasswordDatabase) DeleteEntry(site string) error {
	for i := range db.Entries {
		if db.Entries[i].Site == site {
			db.Entries[i].Wipe()
			db.Entries = append(db.Entries[:i], db.Entries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("entry not found: %s", site)
}

// present all entiry  content
func (db *PasswordDatabase) ListAllEntries() []PasswordEntry {
	return db.Entries
}

// PASSWORD GENERATION
// GeneratePassword creates a random password based on user-defined criteria.
func GeneratePassword(length int, useUpper, useLower, useDigits, useSymbols bool) (string, error) {
	const ( // define content that has upper/lower/digitand symbols
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		symbols   = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	)

	var charset string
	if useLower {
		charset += lowercase
	}
	if useUpper {
		charset += uppercase
	}
	if useDigits {
		charset += digits
	}
	if useSymbols {
		charset += symbols
	}

	if charset == "" {
		return "", errors.New("at least one character set must be selected")
	}

	password := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		password[i] = charset[num.Int64()]
	}

	return string(password), nil
}

// readPassword securely reads a password from the command line without echoing the input.
func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	// Windows-compatible password reading
	if runtime.GOOS == "windows" {
		oldState, err := term.MakeRaw(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		// Ensure the original terminal state is restored
		defer term.Restore(int(syscall.Stdin), oldState)
	}

	var password []byte // define a new variable byte list for password
	buf := make([]byte, 1)

	for {
		n, err := os.Stdin.Read(buf) // Read a single byte from standard input.
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}

		char := buf[0]

		if char == '\n' || char == '\r' {
			fmt.Println()
			break
		}

		if char == 127 || char == 8 { // Handle Backspace (ASCII 127/Delete or 8/Backspace).
			if len(password) > 0 {
				password[len(password)-1] = 0
				password = password[:len(password)-1]
				fmt.Print("\b \b")
			}
			continue
		}

		if char == 3 { // Handle Ctrl+C (ASCII 3).
			fmt.Println()
			secureWipeBytes(password)
			return "", errors.New("interrupted")
		}

		if char < 32 { // Filter out other control characters (e.g., Tab).
			continue
		}

		password = append(password, char) // append it to the password and print an asterisk echo.
		fmt.Print("*")
	}

	result := string(password)
	secureWipeBytes(password) //Wipe the original mutable byte slice from memor
	return result, nil
}

// readInput reads user text inpuut
func readInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin) // read fron new input of the user
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// clearScreen clears the terminal window using platform-specific commands.
func clearScreen() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		fmt.Print("\033[H\033[2J")
	}
}

// maskPassword takes a string and returns an equal-length string of star
func maskPassword(password string) string {
	return strings.Repeat("•", len(password))
}

// PASSWORD strength

// checks a password against a minimum set of security policies.
func validatePasswordStrength(password string) (bool, []string) {
	var errors []string

	if len(password) < 12 { // check if length is >12
		errors = append(errors, "❌ Must be at least 12 characters long")
	}

	hasUpper := false
	for _, char := range password { // loop to check if upper case exsit
		if char >= 'A' && char <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper { // check if it has upper char
		errors = append(errors, "❌ Must contain at least one uppercase letter (A-Z)")
	}

	hasLower := false
	for _, char := range password { // check if it has lower case
		if char >= 'a' && char <= 'z' {
			hasLower = true
			break
		}
	}
	if !hasLower {
		errors = append(errors, "❌ Must contain at least one lowercase letter (a-z)")
	}

	hasDigit := false
	for _, char := range password { // loop to check if number case exsit
		if char >= '0' && char <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit { //check if it has a number
		errors = append(errors, "❌ Must contain at least one digit (0-9)")
	}

	hasSpecial := false
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, char := range password { // loop to check if symbol case exsit
		for _, special := range specialChars {
			if char == special {
				hasSpecial = true
				break
			}
		}
		if hasSpecial {
			break
		}
	}
	if !hasSpecial { // check if it has any special char licke #$
		errors = append(errors, "❌ Must contain at least one special character (!@#$%^&*...)")
	}

	return len(errors) == 0, errors
}

// check the strength of the password by checking length and if it contain upper, lowwer, number and symbol
func getPasswordStrength(password string) (string, string) {
	score := 0

	if len(password) >= 12 {
		score++
	}
	if len(password) >= 16 {
		score++
	}
	if len(password) >= 20 {
		score++
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		if char >= 'A' && char <= 'Z' {
			hasUpper = true
		}
		if char >= 'a' && char <= 'z' {
			hasLower = true
		}
		if char >= '0' && char <= '9' {
			hasDigit = true
		}
		if strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char) {
			hasSpecial = true
		}
	}

	if hasUpper {
		score++
	}
	if hasLower {
		score++
	}
	if hasDigit {
		score++
	}
	if hasSpecial {
		score++
	}

	switch {
	case score <= 3:
		return "WEAK", "🔴"
	case score <= 5:
		return "MEDIUM", "🟡"
	case score <= 6:
		return "STRONG", "🟢"
	default:
		return "VERY STRONG", "💚"
	}
}

// checking for duplicates and weak passwords

// DuplicatePasswordGroup is a structure to hold information about groups of sites which share the same (hashed) password
type DuplicatePasswordGroup struct {
	PasswordHash string
	Sites        []string
	Count        int
}

// identify sites with weak passwords
type WeakPasswordEntry struct {
	Site     string
	Username string
}

// hash pasword for comparsion
func hashPassword(password string) string {
	hash := 0
	for _, char := range password {
		hash = (hash << 5) - hash + int(char)
	}
	return fmt.Sprintf("%x", hash)
}

// FindDuplicatePasswords scans the entire database for entries that share the same password.
func (db *PasswordDatabase) FindDuplicatePasswords() []DuplicatePasswordGroup {
	passwordMap := make(map[string][]string)

	for i := range db.Entries {
		if db.Entries[i].Password == "" {
			continue
		}
		// copy the password string to a local variable.
		tempPassword := db.Entries[i].Password
		passHash := hashPassword(tempPassword) //generate the hash for the temporary password.
		passwordMap[passHash] = append(passwordMap[passHash], db.Entries[i].Site)
		secureWipeString(&tempPassword) //wipe the temporary password from memory
	}

	var duplicates []DuplicatePasswordGroup // create a list of duplicates password
	for passHash, sites := range passwordMap {
		if len(sites) > 1 {
			duplicates = append(duplicates, DuplicatePasswordGroup{ // Found a duplicate: collect the group data.
				PasswordHash: passHash,
				Sites:        sites,
				Count:        len(sites),
			})
		}
	}
	// Clean up memory.
	passwordMap = nil
	runtime.GC()

	return duplicates
}

// FindWeakPasswords scans the database and identifies all entries whose passwords are weak catogrized
func (db *PasswordDatabase) FindWeakPasswords() []WeakPasswordEntry {
	var weakPasswords []WeakPasswordEntry // create a new list to store weak pass site

	for i := range db.Entries { // loop over every enteries
		tempPassword := db.Entries[i].Password

		isValid, _ := validatePasswordStrength(tempPassword) //Run the strength checks

		var isWeak bool
		if !isValid {
			isWeak = true
		} else {
			strength, _ := getPasswordStrength(tempPassword)
			isWeak = (strength == "WEAK")
		}

		secureWipeString(&tempPassword) // clean memory

		if isWeak { // check if it is weak and add it to weak password entry
			weakPasswords = append(weakPasswords, WeakPasswordEntry{
				Site:     db.Entries[i].Site,
				Username: db.Entries[i].Username,
			})
		}
	}

	return weakPasswords // return list of weak pass website name
}

// PASSWORD MANAGER

// PasswordManager is the main application struct, holding the state of the manager.
type PasswordManager struct {
	db           *PasswordDatabase
	salt         []byte
	filepath     string
	masterPw     *SecureString
	locked       bool
	lastActivity time.Time     // check list actiivity user did
	lockTimeout  time.Duration // duration left to lock out
	stopMonitor  chan bool
	forceExit    chan bool
	cloudSync    CloudSyncConfig // store the path of syncronzation option
}

// NewPasswordManager is the constructor for the main PasswordManager object.
func NewPasswordManager(filepath string) *PasswordManager {
	pm := &PasswordManager{
		filepath:     filepath,
		locked:       true,
		lockTimeout:  2 * time.Minute, // Default auto-lock time
		lastActivity: time.Now(),
		stopMonitor:  make(chan bool), // Initialize stop channel.
		forceExit:    make(chan bool),
	}

	pm.loadCloudSyncConfig() // Loads any existing cloud sync settings from a configuration file.
	return pm
}

// updateActivity resets the last activity timer.
func (pm *PasswordManager) updateActivity() {
	pm.lastActivity = time.Now()
}

// determines if the session has been inactive long enough to lock.
func (pm *PasswordManager) checkTimeout() bool {
	if pm.locked {
		return false
	}

	elapsed := time.Since(pm.lastActivity)
	if elapsed >= pm.lockTimeout { // lock the session if time exceed 2 mins
		return true
	}
	return false
}

// calculates how much time is left before the auto-lock triggers.
func (pm *PasswordManager) getRemainingTime() time.Duration {
	elapsed := time.Since(pm.lastActivity)
	remaining := pm.lockTimeout - elapsed // calculate remaining time of session after user didn't activate
	if remaining < 0 {
		return 0
	}
	return remaining
}

// continuously check for inactivity inorder to lock it
func (pm *PasswordManager) startTimeoutMonitor() {
	go func() {
		ticker := time.NewTicker(1 * time.Second) // Creates a ticker that sends a signal every second.
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if pm.checkTimeout() {
					clearScreen()
					fmt.Println("🔒 SESSION TIMED OUT!")
					fmt.Println()
					pm.lock()
					pm.forceExit <- true
					return
				}
			case <-pm.stopMonitor:
				return
			}
		}
	}()
}

// sends a signal to the running goroutine to cease monitoring.
func (pm *PasswordManager) stopTimeoutMonitor() {
	select {
	case pm.stopMonitor <- true:
	default:
	}
}

// handles the initial application flow checking for an existingdatabase, prompting for a master password, and handling login or creation
func (pm *PasswordManager) StartupMenu() {
	clearScreen()
	// Check if the database file already exists on disk.
	_, err := os.Stat(pm.filepath)
	fileExists := !os.IsNotExist(err)
	// --- Existing Database Found (Login Flow) ---
	if fileExists {
		fmt.Println("📁 Database file found: " + pm.filepath)
		fmt.Println()

		for {
			masterPw, err := readPassword("🔐 Enter Master Password: ") //ask user to enter pass
			if err != nil {
				fmt.Printf("❌ Error reading password: %v\n", err)
				continue
			}

			if masterPw == "" { // check if user enter empty string ask him to reenter
				fmt.Println("❌ Password cannot be empty")
				continue
			}

			db, salt, err := LoadDatabase(masterPw, pm.filepath)
			if err != nil {
				fmt.Println("❌ Incorrect master password or corrupted database")
				fmt.Println()

				secureWipeString(&masterPw)

				retry := readInput("Try again? (y/n): ")
				if strings.ToLower(retry) != "y" {
					os.Exit(0)
				}
				continue
			}

			pm.db = db
			pm.salt = salt
			pm.masterPw = NewSecureString(masterPw) // check the enetered pass with the stored encrypted one
			secureWipeString(&masterPw)             // clean the memory
			pm.locked = false
			pm.lastActivity = time.Now()

			fmt.Println("✅ Database unlocked successfully!")
			time.Sleep(2 * time.Second)

			pm.startTimeoutMonitor()
			break
		}
		// if data base not exit ask the user to ener pass and create new datbase file
	} else {
		fmt.Println("📝 No database found. Let's create a new one!")
		fmt.Println()
		fmt.Println("Master Password Requirements:")
		fmt.Println("  • At least 12 characters")
		fmt.Println("  • One uppercase letter (A-Z)")
		fmt.Println("  • One lowercase letter (a-z)")
		fmt.Println("  • One digit (0-9)")
		fmt.Println("  • One special character (!@#$%^&*...)")
		fmt.Println()

		for {
			masterPw, err := readPassword("🔐 Create Master Password: ") // ask user to enter pass
			if err != nil {
				fmt.Printf("❌ Error reading password: %v\n", err)
				continue
			}

			if masterPw == "" {
				fmt.Println("❌ Password cannot be empty")
				continue
			}

			isValid, validationErrors := validatePasswordStrength(masterPw) // check the validety of entered pass
			if !isValid {
				fmt.Println("\n  Password does not meet requirements:")
				for _, errMsg := range validationErrors {
					fmt.Println("  " + errMsg)
				}
				fmt.Println()
				secureWipeString(&masterPw)
				continue
			}

			strength, icon := getPasswordStrength(masterPw) // check the strength
			fmt.Printf("\n%s Password Strength: %s\n", icon, strength)
			fmt.Println()

			confirmPw, err := readPassword(" Confirm Master Password: ") // ask the user to reenter pass for comfirmation
			if err != nil {
				fmt.Printf("❌ Error reading password: %v\n", err)
				secureWipeString(&masterPw)
				continue
			}

			if masterPw != confirmPw {
				fmt.Println("❌ Passwords do not match")
				secureWipeString(&masterPw)
				secureWipeString(&confirmPw)
				continue
			}

			secureWipeString(&confirmPw) //clean memory

			err = CreateDatabase(masterPw, pm.filepath) // create the database file
			if err != nil {
				fmt.Printf("❌ Error creating database: %v\n", err)
				secureWipeString(&masterPw)
				os.Exit(1)
			}

			db, salt, err := LoadDatabase(masterPw, pm.filepath) // load the encrypted infor with salt to file path
			if err != nil {
				fmt.Printf("❌ Error loading database: %v\n", err)
				secureWipeString(&masterPw) // clean the memory
				os.Exit(1)
			}

			pm.db = db     // create database
			pm.salt = salt // get the salt
			pm.masterPw = NewSecureString(masterPw)
			secureWipeString(&masterPw)
			pm.locked = false
			pm.lastActivity = time.Now()

			fmt.Println("✅ Database created successfully!")
			time.Sleep(2 * time.Second)

			pm.startTimeoutMonitor()
			break
		}
	}
}

// shows all user option (add, delete, update, audit, list, change password, retrieve, lock, generate pass)
func (pm *PasswordManager) MainMenu() {
	for {
		select {
		case <-pm.forceExit:
			fmt.Println("\nPress Enter to exit...")
			readInput("")
			return
		default:
		}

		clearScreen()

		remaining := pm.getRemainingTime() // check remain time for inactivity
		minutes := int(remaining.Minutes())
		seconds := int(remaining.Seconds()) % 60
		fmt.Printf("⏱️  Auto-lock in: %dm %ds\n\n", minutes, seconds)
		// list all option user has
		fmt.Println(" MAIN MENU")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("1. 📝 Add New Password")
		fmt.Println("2. 🔍 Retrieve Password")
		fmt.Println("3. ✏️  Update Password")
		fmt.Println("4. 🗑️  Delete Password")
		fmt.Println("5. 📜 List All Passwords")
		fmt.Println("6. 🎲 Generate Random Password")
		fmt.Println("7. 🔍 Security Audit")
		fmt.Println("8. ☁️  Cloud Sync Setup")
		fmt.Println("9. 🔑 Change Master Password")
		fmt.Println("10. 🔒 Lock & Exit")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println()

		choice := readInput("Select option (1-10): ")
		pm.updateActivity()
		// based on user option activate the function relate to it
		switch choice {
		case "1":
			pm.addPassword()
		case "2":
			pm.retrievePassword()
		case "3":
			pm.updatePassword()
		case "4":
			pm.deletePassword()
		case "5":
			pm.listPasswords()
		case "6":
			pm.generatePassword()
		case "7":
			pm.auditPasswords()
		case "8":
			pm.setupCloudSync()
		case "9":
			pm.changeMasterPassword()
		case "10":
			pm.stopTimeoutMonitor()
			pm.lock()
			return
		default:
			fmt.Println("❌ Invalid option")
			time.Sleep(1 * time.Second)
		}
	}
}

// allwo user to change the pass
func (pm *PasswordManager) changeMasterPassword() {
	pm.updateActivity()
	clearScreen()
	fmt.Println(" CHANGE MASTER PASSWORD")
	fmt.Println()
	fmt.Println("  WARNING: This will re-encrypt your entire database!")
	fmt.Println("  Make sure you remember your new password!")
	fmt.Println()

	confirm := readInput("Continue? (y/n): ") // confirm with user that he/she want to cahnge pass
	if strings.ToLower(confirm) != "y" {
		fmt.Println("❌ Operation cancelled")
		time.Sleep(1 * time.Second)
		return
	}

	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("STEP 1: Verify Current Master Password")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	maxAttempts := 3                                      // allow three attempt to enter current pass if they are 3 times false they can't chane pass
	for attempt := 1; attempt <= maxAttempts; attempt++ { // assk user toenter pass
		currentPassword, err := readPassword(fmt.Sprintf(" Enter Current Master Password (Attempt %d/%d): ", attempt, maxAttempts))
		if err != nil { // check if password is not null
			fmt.Printf("❌ Error reading password: %v\n", err)
			continue
		}

		if currentPassword == "" { // check if password is empty
			fmt.Println("❌ Password cannot be empty")
			continue
		}

		_, _, err = LoadDatabase(currentPassword, pm.filepath) // if it is not empty
		if err != nil {
			fmt.Println("❌ Incorrect current password")
			secureWipeString(&currentPassword)
			if attempt < maxAttempts {
				fmt.Println()
				continue
			} else { // check the mac number of atempt
				fmt.Println("\n  Maximum attempts reached. Returning to main menu for security.")
				time.Sleep(2 * time.Second)
				return
			}
		}

		secureWipeString(&currentPassword)
		fmt.Println("✅ Current password verified!")
		break
	}

	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("STEP 2: Create New Master Password")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("New Master Password Requirements:")
	fmt.Println("  • At least 12 characters")
	fmt.Println("  • One uppercase letter (A-Z)")
	fmt.Println("  • One lowercase letter (a-z)")
	fmt.Println("  • One digit (0-9)")
	fmt.Println("  • One special character (!@#$%^&*...)")
	fmt.Println()

	var newPassword string
	for {
		newPass, err := readPassword("🔐 Enter New Master Password: ") // ask user to enter new pass
		if err != nil {
			fmt.Printf("❌ Error reading password: %v\n", err)
			continue
		}

		if newPass == "" {
			fmt.Println("❌ Password cannot be empty")
			continue
		}

		if newPass == pm.masterPw.String() { //compare it with old pass
			fmt.Println("❌ New password must be different from current password")
			fmt.Println()
			secureWipeString(&newPass)
			continue
		}

		isValid, validationErrors := validatePasswordStrength(newPass) // validate strength of new pass
		if !isValid {
			fmt.Println("\n⚠️  Password does not meet requirements:")
			for _, errMsg := range validationErrors {
				fmt.Println("  " + errMsg)
			}
			fmt.Println()
			secureWipeString(&newPass)
			continue
		}

		strength, icon := getPasswordStrength(newPass) // check the strength of new password
		fmt.Printf("\n%s Password Strength: %s\n", icon, strength)
		fmt.Println()

		confirmPass, err := readPassword("🔐 Confirm New Master Password: ") // confirm the new pass by asking user to reenter it
		if err != nil {
			fmt.Printf("❌ Error reading password: %v\n", err)
			secureWipeString(&newPass)
			continue
		}

		if newPass != confirmPass {
			fmt.Println("❌ Passwords do not match")
			fmt.Println()
			secureWipeString(&newPass)
			secureWipeString(&confirmPass)
			continue
		}

		secureWipeString(&confirmPass) // clear the memory
		newPassword = newPass
		break
	}

	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("STEP 3: Re-encrypting Database")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("🔄 Generating new encryption salt...")
	// reencrypt database based on new pass and generate new path
	newSalt, err := GenerateSalt() // generate new salt
	if err != nil {
		fmt.Printf("❌ Error generating salt: %v\n", err)
		secureWipeString(&newPassword)
		readInput("\nPress Enter to continue...")
		return
	}

	fmt.Println("✅ New salt generated")
	fmt.Println("🔄 Re-encrypting all password entries...")

	err = SaveDatabase(pm.db, newPassword, pm.filepath, newSalt) // save new encrypted file
	if err != nil {
		fmt.Printf("❌ Error saving database: %v\n", err)
		fmt.Println("⚠️  Database may be corrupted. Please check your backup!")
		secureWipeString(&newPassword)
		readInput("\nPress Enter to continue...")
		return
	}

	pm.masterPw.Wipe()
	pm.masterPw = NewSecureString(newPassword)
	secureWipeString(&newPassword)
	pm.salt = newSalt

	fmt.Println("✅ Database re-encrypted successfully!")
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("✅ MASTER PASSWORD CHANGED SUCCESSFULLY!")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println(" Security Summary:")
	fmt.Println("  • Master password updated")
	fmt.Println("  • New encryption salt generated")
	fmt.Println("  • All passwords re-encrypted")
	fmt.Println("  • Database saved securely")
	fmt.Println("  • Remember your new master password")
	fmt.Println("  • There is NO way to recover it if forgotten")

	readInput("Press Enter to continue...")
	pm.updateActivity()
}

// function that check the number of duplicates pass with number of weak pass
func (pm *PasswordManager) auditPasswords() {
	pm.updateActivity()
	clearScreen()

	fmt.Println("🔍 PASSWORD SECURITY AUDIT")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	if len(pm.db.Entries) == 0 { // if data base is empty no audit need
		fmt.Println("📭 No passwords to audit")
		readInput("\nPress Enter to continue...")
		return
	}

	duplicates := pm.db.FindDuplicatePasswords() // define dupicate list that contains all entry of duplicates
	weakPasswords := pm.db.FindWeakPasswords()   // define weak list that contains all weak pass

	fmt.Println("📊 AUDIT SUMMARY")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Total Passwords: %d\n", len(pm.db.Entries))
	fmt.Printf("Duplicate Passwords: %d groups\n", len(duplicates))
	fmt.Printf("Weak Passwords: %d\n", len(weakPasswords))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	if len(duplicates) > 0 { // check if number of duplictaes >0 warm the user and suggest recommendation
		fmt.Println("⚠️  DUPLICATE PASSWORDS DETECTED")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("Using the same password across multiple services is dangerous!")
		fmt.Println("If one site is breached, ALL these accounts are at risk.")
		fmt.Println()

		for i, dup := range duplicates { // loop over duplicate list and print the server names that have same pass
			fmt.Printf("%d. Same password used by %d sites:\n", i+1, dup.Count)
			fmt.Println("   Sites:")
			for _, site := range dup.Sites {
				fmt.Printf("   • %s\n", site)
			}
			fmt.Println()
		}

		fmt.Println("💡 RECOMMENDATION:")
		fmt.Println("   Change passwords for these sites to unique, strong passwords ASAP.")
		fmt.Println()
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println()
	} else { // no duplicates find message if number is zero
		fmt.Println("✅ No duplicate passwords found!")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println()
	}

	if len(weakPasswords) > 0 { // check number of weak password and warm user
		fmt.Println("⚠️  WEAK PASSWORDS DETECTED")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("These passwords don't meet security standards or are too weak.")
		fmt.Println()

		for i, weak := range weakPasswords {
			fmt.Printf("%d. Site: %-28s  Username: %s\n", i+1, weak.Site, weak.Username)
			fmt.Println()
		}

		fmt.Println("💡 RECOMMENDATION:")
		fmt.Println("   Update these passwords to meet security requirements:")
		fmt.Println("   • At least 12 characters long")
		fmt.Println("   • Mix of uppercase, lowercase, digits, and symbols")
		fmt.Println()
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println()
	} else { // no weak pass fouud message in case all password are strong
		fmt.Println("✅ All passwords meet security requirements!")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println()
	}

	for i := range duplicates {
		duplicates[i].PasswordHash = ""
		duplicates[i].Sites = nil
	}
	duplicates = nil

	for i := range weakPasswords {
		weakPasswords[i].Site = ""
		weakPasswords[i].Username = ""
	}
	weakPasswords = nil
	runtime.GC()

	readInput("\nPress Enter to continue...")
}

// function to add password
func (pm *PasswordManager) addPassword() {
	pm.updateActivity()
	clearScreen()

	fmt.Println("📝 ADD NEW PASSWORD")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	site := readInput("Site/Service (e.g., Facebook): ")
	if site == "" {
		fmt.Println("❌ Site cannot be empty")
		readInput("\nPress Enter to continue...")
		return
	}

	_, err := pm.db.GetEntry(site)
	if err == nil {
		fmt.Println("⚠️  Entry already exists for this site!")
		overwrite := readInput("Overwrite? (y/n): ")
		if strings.ToLower(overwrite) != "y" {
			return
		}
	}

	username := readInput("Username/Email: ") // get user input for web page

	fmt.Println()
	fmt.Println("Password options:") // ask him to chose if they wan to enter pass manual or generate random one
	fmt.Println("1. Enter password manually")
	fmt.Println("2. Generate random password")
	choice := readInput("Choose (1/2): ")

	var password string

	if choice == "2" { // generate a random pass for user based onsize he gave >=12
		fmt.Println()
		lengthStr := readInput("Password length (default 16): ")
		length := 16
		if lengthStr != "" {
			fmt.Sscanf(lengthStr, "%d", &length)
		}

		genPass, err := GeneratePassword(length, true, true, true, true)
		if err != nil {
			fmt.Printf("❌ Error generating password: %v\n", err)
			readInput("\nPress Enter to continue...")
			return
		}
		password = genPass

		strength, icon := getPasswordStrength(password)
		fmt.Println()
		fmt.Printf("✅ Generated password: %s\n", password)
		fmt.Printf("%s Password Strength: %s\n", icon, strength)

	} else { // allow him to enter any pass if password is weak notify him and recommend to add a strong er pass
		for {
			pass, _ := readPassword("Password: ")

			if pass == "" {
				fmt.Println("\n❌ Password cannot be empty")
				retry := readInput("Try again? (y/n): ")
				if strings.ToLower(retry) != "y" {
					return
				}
				continue
			}

			fmt.Println()

			isValid, validationErrors := validatePasswordStrength(pass) // validate strength of pass
			strength, icon := getPasswordStrength(pass)

			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			fmt.Printf("%s Password Strength: %s\n", icon, strength)
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

			if !isValid || strength == "WEAK" { // if it weak ask recommend to change it to good one
				fmt.Println()
				fmt.Println("⚠️  WARNING: This password is WEAK!")

				if !isValid {
					fmt.Println("\n❌ Password does not meet security requirements:")
					for _, errMsg := range validationErrors {
						fmt.Println("  " + errMsg)
					}
				}

				fmt.Println() // give him recommendation to change pass since it is weak
				fmt.Println("🔒 Security Recommendations:")
				fmt.Println("  • Use at least 12 characters")
				fmt.Println("  • Mix uppercase, lowercase, digits, and symbols")
				fmt.Println("  • Consider using option 2 to generate a strong password")
				fmt.Println()

				confirm := readInput("⚠️  Save this WEAK password anyway? (y/n): ")

				if strings.ToLower(confirm) == "y" { // allow him to save with warning
					fmt.Println("\n⚠️  Weak password accepted (not recommended)")
					password = pass
					break
				} else {
					fmt.Println("\n✅ Good choice! Let's try again.")
					fmt.Println()
					secureWipeString(&pass)
					retry := readInput("Enter a different password? (y/n): ")
					if strings.ToLower(retry) != "y" {
						return
					}
					continue
				}
			} else if strength == "MEDIUM" { // also in case of meduim pass we ask user to change pass
				fmt.Println()
				fmt.Println("💡 This password is MEDIUM strength.")
				fmt.Println("   Consider using a stronger password for better security.")
				fmt.Println()

				confirm := readInput("Continue with this password? (y/n): ")
				if strings.ToLower(confirm) == "y" {
					password = pass
					break
				} else {
					fmt.Println()
					secureWipeString(&pass)
					retry := readInput("Enter a different password? (y/n): ")
					if strings.ToLower(retry) != "y" {
						return
					}
					continue
				}
			} else {
				fmt.Println()
				fmt.Println("✅ Excellent! This is a strong password.")
				password = pass
				break
			}
		}
	}

	notes := readInput("\nNotes (optional): ") // take user note for web

	if err == nil {
		pm.db.UpdateEntry(site, username, password, notes)
	} else {
		pm.db.AddEntry(site, username, password, notes) // add the new pass to list of entry
	}

	secureWipeString(&password) // clean memory

	err = SaveDatabase(pm.db, pm.masterPw.String(), pm.filepath, pm.salt)
	if err != nil {
		fmt.Printf("❌ Error saving database: %v\n", err)
		readInput("\nPress Enter to continue...")
		return
	}

	fmt.Println("\n✅ Password saved successfully!")
	readInput("\nPress Enter to continue...")
}

// retrieve the password for user if he/she want to see the pass for given website or service
func (pm *PasswordManager) retrievePassword() {
	pm.updateActivity()
	clearScreen()
	fmt.Println("🔍 RETRIEVE PASSWORD")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	site := readInput("Enter site/service name: ") // ask user to enter web site name

	entry, err := pm.db.GetEntry(site) // sheck if it is exist
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		readInput("\nPress Enter to continue...")
		return
	}

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Site:     %s\n", entry.Site)
	fmt.Printf("Username: %s\n", entry.Username)
	fmt.Printf("Password: %s\n", maskPassword(entry.Password))
	if entry.Notes != "" {
		fmt.Printf("Notes:    %s\n", entry.Notes)
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	fmt.Println()
	fmt.Println("📋 How would you like to access the password?")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("1. 📋 Copy to clipboard (auto-clears in 10 seconds)")
	fmt.Println("2. 👁️  Show on screen (auto-clears in 10 seconds)")
	fmt.Println("3. ❌ Cancel")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	choice := readInput("\nSelect option (1-3): ") // give user 3 option easer to copy it in clipboard, show it on scree, or cancel request
	pm.updateActivity()

	switch choice { // if he chose copy clipborad password will be clear from memory and clipboard after 10 sec
	case "1":
		err := clipboard.WriteAll(entry.Password)
		if err != nil {
			fmt.Printf("\n❌ Error copying to clipboard: %v\n", err)
			readInput("\nPress Enter to continue...")
			return
		}

		clearScreen()

		fmt.Println("✅ PASSWORD COPIED TO CLIPBOARD")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Printf("Site: %s\n", entry.Site)
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("\n🔐 Security Features:")
		fmt.Println("  • Password copied to clipboard")
		fmt.Println("  • Clipboard will auto-clear in 10 seconds")
		fmt.Println("  • Password NOT displayed on screen")
		fmt.Println()

		for i := 10; i > 0; i-- { // check the time remaining for the end of 10 sec
			fmt.Printf("\r⏱️  Clearing clipboard in %2d seconds... ", i)
			time.Sleep(1 * time.Second)
			pm.updateActivity()
		}

		err = clipboard.WriteAll("")
		if err != nil {
			fmt.Printf("\n⚠️  Warning: Failed to clear clipboard: %v\n", err)
		} else {
			fmt.Print("\r🔒 Clipboard cleared successfully!       \n")
		}

		fmt.Println()
		readInput("Press Enter to continue...")

	case "2": // if use chose show password, it will be shown on screen for 10 sec and it will be cleaned from memiry and garbage
		clearScreen()

		fmt.Println("👁️  PASSWORD VISIBLE ON SCREEN")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Printf("Site:     %s\n", entry.Site)
		fmt.Printf("Username: %s\n", entry.Username)
		fmt.Printf("Password: %s\n", entry.Password)
		if entry.Notes != "" {
			fmt.Printf("Notes:    %s\n", entry.Notes)
		}
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println()
		fmt.Println("⚠️  WARNING: Password is visible on screen!")
		fmt.Println("🔒 Security: Screen will auto-clear in 10 seconds")
		fmt.Println("💡 Tip: Press Enter to clear immediately")
		fmt.Println()

		done := make(chan bool, 1)
		userInput := make(chan bool, 1)

		go func() {
			for i := 10; i > 0; i-- {
				select {
				case <-done:
					return
				default:
					if i <= 10 {
						fmt.Printf("\r⚠️  AUTO-CLEARING IN %2d SECONDS... (Press Enter to clear now)  ", i)
					} else {
						fmt.Printf("\r⏱️  Auto-clearing in %2d seconds... (Press Enter to clear now)  ", i)
					}
					time.Sleep(1 * time.Second)
					pm.updateActivity()
				}
			}
			select {
			case <-done:
			default:
				done <- true
			}
		}()

		go func() {
			readInput("")
			select {
			case <-done:
			default:
				userInput <- true
				done <- true
			}
		}()

		<-done

		clearScreen()

		select {
		case <-userInput:
			fmt.Println("🔒 Screen cleared by user!")
		default:
			fmt.Println("🔒 Screen auto-cleared after 10 seconds!")
		}

		fmt.Println("✅ Password has been securely removed from display")
		fmt.Println()
		time.Sleep(1 * time.Second)

	case "3": // cancel the option of retriveing
		fmt.Println("\n❌ Cancelled")
		time.Sleep(1 * time.Second)
		return

	default:
		fmt.Println("\n❌ Invalid option")
		time.Sleep(1 * time.Second)
	}
}

// this func allow user to update his/her pass
func (pm *PasswordManager) updatePassword() {
	pm.updateActivity()
	clearScreen()
	fmt.Println("✏️  UPDATE PASSWORD")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	site := readInput("Enter site/service name: ") // ask user to enter site that he want to update pass

	entry, err := pm.db.GetEntry(site)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		readInput("\nPress Enter to continue...")
		return
	}

	fmt.Println("\nCurrent entry:")
	fmt.Printf("Username: %s\n", entry.Username)
	fmt.Printf("Password: %s\n", maskPassword(entry.Password))
	fmt.Println()
	// give the user option to change username
	username := readInput(fmt.Sprintf("New Username (or press Enter to keep '%s'): ", entry.Username))
	if username == "" {
		username = entry.Username
	}
	// give him option to change new pass
	password, _ := readPassword("New Password (or press Enter to keep current): ")
	if password == "" {
		password = entry.Password
	}
	//give him option to change the notes that he writes
	notes := readInput(fmt.Sprintf("New Notes (or press Enter to keep '%s'): ", entry.Notes))
	if notes == "" {
		notes = entry.Notes
	}

	err = pm.db.UpdateEntry(site, username, password, notes) // use update func entry to edit pass in enty list
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		secureWipeString(&password)
		readInput("\nPress Enter to continue...")
		return
	}

	secureWipeString(&password) // clean the memory

	err = SaveDatabase(pm.db, pm.masterPw.String(), pm.filepath, pm.salt)
	if err != nil {
		fmt.Printf("❌ Error saving database: %v\n", err)
		readInput("\nPress Enter to continue...")
		return
	}

	fmt.Println("\n✅ Password updated successfully!")
	readInput("\nPress Enter to continue...")
}

// remove the entry of the given web from password manger
func (pm *PasswordManager) deletePassword() {
	pm.updateActivity()
	clearScreen()

	fmt.Println("🗑️  DELETE PASSWORD")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	site := readInput("Enter site/service name: ") // ask user to enter web name

	_, err := pm.db.GetEntry(site)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		readInput("\nPress Enter to continue...")
		return
	}

	confirm := readInput(fmt.Sprintf("⚠️  Delete entry for '%s'? (y/n): ", site)) // confirm from user to delete
	if strings.ToLower(confirm) != "y" {
		fmt.Println("❌ Deletion cancelled")
		readInput("\nPress Enter to continue...")
		return
	}

	err = pm.db.DeleteEntry(site) // check for an error, and delete the password entry
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		readInput("\nPress Enter to continue...")
		return
	}

	err = SaveDatabase(pm.db, pm.masterPw.String(), pm.filepath, pm.salt) // save updated version of entry pass in database
	if err != nil {
		fmt.Printf("❌ Error saving database: %v\n", err)
		readInput("\nPress Enter to continue...")
		return
	}

	fmt.Println("\n✅ Password deleted successfully!")
	readInput("\nPress Enter to continue...")
}

// show all  website name with the username of eachone
func (pm *PasswordManager) listPasswords() {
	pm.updateActivity()
	clearScreen()

	fmt.Println("📜 ALL PASSWORDS")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	entries := pm.db.ListAllEntries() // get all entries

	if len(entries) == 0 {
		fmt.Println("📭 No passwords stored yet")
	} else {
		fmt.Printf("    %-28s %s \n", "Site", "UserName")
		fmt.Println("-------------------------------------------------")

		for i, entry := range entries { // print all user name and websitte name for all password entry
			fmt.Printf("%d.  %-28s %s\n", i+1, entry.Site, entry.Username)
		}
		fmt.Printf("\nTotal: %d password(s)\n", len(entries))
	}

	readInput("\nPress Enter to continue...")
}

// thos function allow user to generate a random password containing number, special char, upper and lower case char with length >=10
func (pm *PasswordManager) generatePassword() {
	pm.updateActivity()
	clearScreen()

	fmt.Println("🎲 GENERATE RANDOM PASSWORD")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	lengthStr := readInput("Password length (default 16): ") // ask user to enter length of pass that he want to generate
	length := 16                                             // default is 16
	if lengthStr != "" {
		fmt.Sscanf(lengthStr, "%d", &length)
	}

	if length < 10 { // if user input len is <10 reject it
		fmt.Println("❌ Length must be at least 10")
		readInput("\nPress Enter to continue...")
		return
	}

	password, err := GeneratePassword(length, true, true, true, true) // gereate password that match all strength condition
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		readInput("\nPress Enter to continue...")
		return
	}

	fmt.Println("\n✅ Generated Password:")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  %s\n", password)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("\n💡 Copy this password now!")

	readInput("\nPress Enter to continue...")
	secureWipeString(&password)
}

// this func is to lock the password manger, cleacn the memory before lock and syncro backup based on given input
func (pm *PasswordManager) lock() {
	clearScreen()
	fmt.Println("🔒 Locking password manager...")

	if pm.cloudSync.Enabled { // check if syn is enabled to saved the updated version of syn
		fmt.Println("☁️  Syncing to cloud...")
		err := pm.syncToCloudOnExit() // check for any error
		if err != nil {               // if error exist send notification
			fmt.Printf("⚠️  Cloud sync failed: %v\n", err)
			fmt.Println("💾 Database saved locally")
		} else { // else syn on cloud
			fmt.Println("✅ Synced to cloud successfully!")
		}
	}
	// clear memory
	if pm.db != nil {
		pm.db.Wipe()
	}

	if pm.masterPw != nil {
		pm.masterPw.Wipe()
	}

	if pm.salt != nil {
		secureWipeBytes(pm.salt)
		pm.salt = nil
	}

	pm.db = nil
	pm.locked = true

	runtime.GC()

	time.Sleep(1 * time.Second)
	fmt.Println("✅ All sensitive data wiped from memory")
	fmt.Println("✅ Locked. Goodbye!")
}

// check if sync are enabled
func (pm *PasswordManager) syncToCloudOnExit() error {
	if !pm.cloudSync.Enabled || pm.cloudSync.CloudPath == "" { // check if the path exist and syn is enabled
		return nil
	}

	if _, err := os.Stat(pm.cloudSync.CloudPath); os.IsNotExist(err) {
		return fmt.Errorf("cloud sync folder not found: %s", pm.cloudSync.CloudPath)
	}

	cloudFile := filepath.Join(pm.cloudSync.CloudPath, "passwords.db") // define path of cloud folder

	sourceFile, err := os.Open(pm.filepath) // check the validaiaty of the path given by user
	if err != nil {
		return fmt.Errorf("failed to read database: %v", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(cloudFile) // if no error exist crete the file in cloud path
	if err != nil {
		return fmt.Errorf("failed to write to cloud: %v", err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("failed to sync to cloud: %v", err)
	}

	return nil
}

// this function is to load the updated file after the user lock  the manger app
func (pm *PasswordManager) loadCloudSyncConfig() {
	configFile := "cloud_sync.conf"
	data, err := os.ReadFile(configFile)
	if err != nil {
		pm.cloudSync.Enabled = false
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "enabled=") {
			pm.cloudSync.Enabled = strings.Contains(line, "true")
		} else if strings.HasPrefix(line, "path=") {
			pm.cloudSync.CloudPath = strings.TrimPrefix(line, "path=")
			// No expansion needed - store path as-is
		}
	}
}

// it is used to save the encrypted file using the path given
func (pm *PasswordManager) saveCloudSyncConfig() error {
	configFile := "cloud_sync.conf"

	// Save the path
	content := fmt.Sprintf("enabled=%v\npath=%s\n", pm.cloudSync.Enabled, pm.cloudSync.CloudPath)
	return os.WriteFile(configFile, []byte(content), 0600)
}

// function to set the cloud option, it is not defualt active, user need to setup
func (pm *PasswordManager) setupCloudSync() {
	pm.updateActivity()
	clearScreen()

	fmt.Println("☁️  CLOUD SYNC SETUP")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("🔐 Your database is ALREADY ENCRYPTED with AES-256!")
	fmt.Println()
	fmt.Println("When enabled, your encrypted database will automatically")
	fmt.Println("sync to your cloud folder every time you lock/exit.")
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	if pm.cloudSync.Enabled { // when user already setup, he can update the path disablecloud syn, test path
		fmt.Printf("Current Status: ✅ ENABLED\n")
		fmt.Printf("Cloud Path: %s\n", pm.cloudSync.CloudPath)
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("1. Change cloud path")
		fmt.Println("2. Disable cloud sync")
		fmt.Println("3. Test sync now")
		fmt.Println("4. Cancel")
		fmt.Println()

		choice := readInput("Select option (1-4): ") // get user input
		pm.updateActivity()

		switch choice {
		case "1":
			fmt.Println()
			fmt.Println("Enter new cloud folder path:")
			fmt.Println("Example: C:\\Users\\YourName\\OneDrive\\PasswordManager")
			fmt.Println()
			newPath := readInput("Path: ")

			if newPath == "" {
				fmt.Println("❌ Path cannot be empty")
				readInput("\nPress Enter to continue...")
				return
			}

			if _, err := os.Stat(newPath); os.IsNotExist(err) {
				fmt.Printf("\n⚠️  Folder doesn't exist: %s\n", newPath) // ask user to add his path wher he want to store pass
				create := readInput("Create it now? (y/n): ")
				if strings.ToLower(create) == "y" {
					if err := os.MkdirAll(newPath, 0700); err != nil {
						fmt.Printf("❌ Failed to create folder: %v\n", err)
						readInput("\nPress Enter to continue...")
						return
					}
					fmt.Println("✅ Folder created!")
				} else {
					readInput("\nPress Enter to continue...")
					return
				}
			}

			pm.cloudSync.CloudPath = newPath // save the cloud path
			pm.saveCloudSyncConfig()
			fmt.Println("\n✅ Cloud path updated!")

		case "2":
			confirm := readInput("\nDisable cloud sync? (y/n): ") // allow user to enable the cloud syn
			if strings.ToLower(confirm) == "y" {
				pm.cloudSync.Enabled = false
				pm.saveCloudSyncConfig()
				fmt.Println("✅ Cloud sync disabled")
			}

		case "3":
			fmt.Println("\n🔄 Testing sync...") // allow user to test if syn work
			err := pm.syncToCloudOnExit()
			if err != nil {
				fmt.Printf("❌ Sync failed: %v\n", err)
			} else {
				fmt.Println("✅ Sync successful!")
			}

		case "4":
			return
		}

	} else { // ask the user to enter path if it is not exist before
		fmt.Printf("Current Status: ⚪ DISABLED\n")
		fmt.Println()

		enable := readInput("Enable cloud sync? (y/n): ") // check if they want to enable sync
		if strings.ToLower(enable) != "y" {
			return
		}

		fmt.Println()
		fmt.Println("Enter your cloud sync folder path:")
		fmt.Println("Examples:")
		fmt.Println("  • C:\\Users\\YourName\\OneDrive\\PasswordManager")
		fmt.Println()

		cloudPath := readInput("Path: ") // get the path
		if cloudPath == "" {
			fmt.Println("❌ Path cannot be empty")
			readInput("\nPress Enter to continue...")
			return
		}

		if _, err := os.Stat(cloudPath); os.IsNotExist(err) { // check for thepath
			fmt.Printf("\n⚠️  Folder doesn't exist: %s\n", cloudPath)
			create := readInput("Create it now? (y/n): ")
			if strings.ToLower(create) == "y" {
				if err := os.MkdirAll(cloudPath, 0700); err != nil {
					fmt.Printf("❌ Failed to create folder: %v\n", err)
					readInput("\nPress Enter to continue...")
					return
				}
				fmt.Println("✅ Folder created!")
			} else {
				readInput("\nPress Enter to continue...")
				return
			}
		}

		pm.cloudSync.Enabled = true
		pm.cloudSync.CloudPath = cloudPath
		pm.saveCloudSyncConfig()

		fmt.Println()
		fmt.Println("✅ Cloud sync enabled!")
		fmt.Println()
		fmt.Println("Your encrypted database will now automatically sync")
		fmt.Println("to the cloud every time you lock/exit the application.")
	}

	readInput("\nPress Enter to continue...")
}

// main function

func main() {
	filepath := "passwords.db"

	pm := NewPasswordManager(filepath)
	pm.StartupMenu()
	pm.MainMenu()
}
