package handler

import (
	"a21hc3NpZ25tZW50/client"
	"a21hc3NpZ25tZW50/model"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var UserLogin = make(map[string]model.User)

// DESC: func Auth is a middleware to check user login id, only user that already login can pass this middleware
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("user_login_id")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
			return
		}

		if _, ok := UserLogin[c.Value]; !ok || c.Value == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "userID", c.Value)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// DESC: func AuthAdmin is a middleware to check user login role, only admin can pass this middleware
func AuthAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("user_login_role")
		if err != nil || c.Value != "admin" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login role not Admin"})
			return
		}

		next.ServeHTTP(w, r)
	}) // TODO: replace this
}

func Login(w http.ResponseWriter, r *http.Request) {
	var userLogin model.User
	err := json.NewDecoder(r.Body).Decode(&userLogin)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
		return
	}

	// Check empty field
	if userLogin.ID == "" || userLogin.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "ID or name is empty"})
		return
	}

	// Check if the user exists
	userFilePath := filepath.Join("data", "users.txt")
	userFile, err := os.Open(userFilePath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Cannot read user file"})
		return
	}
	defer userFile.Close()

	scanner := bufio.NewScanner(userFile)
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "_")
		if parts[0] == userLogin.ID && parts[1] == userLogin.Name {
			found = true
			userLogin.Role = parts[2]
			userLogin.StudyCode = parts[3]
			break
		}
	}

	if !found {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user not found"})
		return
	}

	// Save the user login info
	UserLogin[userLogin.ID] = userLogin

	file, err := os.OpenFile("data/users.txt", os.O_RDONLY, 0644)
	role := ""
	if err != nil {
		panic(err)
	}
	fileScanner := bufio.NewScanner(file)
	for fileScanner.Scan() {
		text := fileScanner.Text()
		splited := strings.Split(text, "_")
		if splited[0] == userLogin.ID {
			role = splited[3]
			break
		}
	}

	// Create cookies
	userIDCookie := &http.Cookie{
		Name:  "user_login_id",
		Value: userLogin.ID,
		Path:  "/",
	}
	roleCookie := &http.Cookie{
		Name:  "user_login_role",
		Value: role,
		Path:  "/",
	}

	// Set the cookies
	http.SetCookie(w, userIDCookie)
	http.SetCookie(w, roleCookie)

	// Return the success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(model.SuccessResponse{
		Username: userLogin.ID,
		Message:  "login success",
	}) // TODO: answer here
}

func Register(w http.ResponseWriter, r *http.Request) {
	var newUser model.User
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
		return
	}

	// Check empty field
	if newUser.ID == "" || newUser.Name == "" || newUser.Role == "" || newUser.StudyCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "ID, name, study code or role is empty"})
		return
	}

	// Check role
	if newUser.Role != "admin" && newUser.Role != "user" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "role must be admin or user"})
		return
	}

	// Check study code
	studyListPath := filepath.Join("data", "list-study.txt")
	studyListFile, err := os.Open(studyListPath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "cannot read study list file"})
		return
	}
	defer studyListFile.Close()

	scanner := bufio.NewScanner(studyListFile)
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "_")
		if parts[0] == newUser.StudyCode {
			found = true
			break
		}
	}

	if !found {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "study code not found"})
		return
	}

	// Check if user already exist
	usersPath := filepath.Join("data", "users.txt")
	usersFile, err := os.Open(usersPath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "cannot read users file"})
		return
	}
	defer usersFile.Close()

	scanner = bufio.NewScanner(usersFile)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "_")
		if parts[0] == newUser.ID {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user id already exist"})
			return
		}
	}

	// Save user to file
	usersFile, err = os.OpenFile(usersPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "cannot open users file"})
		return
	}
	defer usersFile.Close()

	line := newUser.ID + "_" + newUser.Name + "_" + newUser.StudyCode + "_" + newUser.Role
	_, err = fmt.Fprintln(usersFile, line)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "cannot write to users file"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(model.SuccessResponse{Message: "register success", Username: newUser.ID}) // TODO: answer here
}

func Logout(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	c, err := r.Cookie("user_login_id")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
		return
	}

	if _, ok := UserLogin[c.Value]; !ok || c.Value == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
		return
	}

	// Remove cookies
	http.SetCookie(w, &http.Cookie{Name: "user_login_id", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "user_login_role", Value: "", Path: "/", MaxAge: -1})

	// Remove user from map
	delete(UserLogin, c.Value)

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(model.SuccessResponse{Username: c.Value, Message: "logout success"}) // TODO: answer here
}

func GetStudyProgram(w http.ResponseWriter, r *http.Request) {
	studyFilePath := filepath.Join("data", "list-study.txt")
	studyFile, err := os.Open(studyFilePath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Cannot read study program file"})
		return
	}
	defer studyFile.Close()

	scanner := bufio.NewScanner(studyFile)
	studyPrograms := make([]model.StudyData, 0)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "_")
		studyPrograms = append(studyPrograms, model.StudyData{Code: parts[0], Name: parts[1]})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(studyPrograms) // TODO: answer here
}

func AddUser(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var user model.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
		return
	}

	// Check if study code exists
	studyFilePath := filepath.Join("data", "list-study.txt")
	studyFile, err := os.Open(studyFilePath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Cannot read study program file"})
		return
	}
	defer studyFile.Close()

	var studies []model.StudyData
	scanner := bufio.NewScanner(studyFile)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "_")
		if len(fields) != 2 {
			continue
		}

		study := model.StudyData{
			Code: fields[0],
			Name: fields[1],
		}

		studies = append(studies, study)
	}

	studyFound := false
	for _, study := range studies {
		if study.Code == user.StudyCode {
			studyFound = true
			break
		}
	}

	if !studyFound {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "study code not found"})
		return
	}

	// Check empty fields
	if user.ID == "" || user.Name == "" || user.StudyCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "ID, name, or study code is empty"})
		return
	}

	// Check if user already exists
	userData, err := ioutil.ReadFile(filepath.Join("data", "users.txt"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Cannot read user file"})
		return
	}

	if strings.Contains(string(userData), user.ID) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user id already exist"})
		return
	}

	// Add user to file
	userData = append(userData, []byte(fmt.Sprintf("%s_%s_%s_user\n", user.ID, user.Name, user.StudyCode))...)
	err = ioutil.WriteFile(filepath.Join("data", "users.txt"), userData, 0644)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Cannot write user file"})
		return
	}

	// Return success response
	success := model.SuccessResponse{
		Username: user.Name,
		Message:  "add user success",
	}

	response, err := json.Marshal(success)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Internal Server Error"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response) // TODO: answer here
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	// Check id parameter
	q := r.URL.Query()
	id, ok := q["id"]
	if !ok || len(id[0]) < 1 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user id is empty"})
		return
	}

	// Check if user already exists
	usersFilePath := filepath.Join("data", "users.txt")
	usersFile, err := os.Open(usersFilePath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Cannot read user file"})
		return
	}
	defer usersFile.Close()

	var lines []string
	scanner := bufio.NewScanner(usersFile)
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "_")
		if parts[0] == id[0] {
			found = true
		} else {
			lines = append(lines, line)
		}
	}

	if !found {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user id not found"})
		return
	}

	// Update file
	usersFile, err = os.Create(usersFilePath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Cannot write user file"})
		return
	}
	defer usersFile.Close()

	for _, line := range lines {
		_, err = fmt.Fprintln(usersFile, line)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Cannot write user file"})
			return
		}
	}

	// Return success response
	success := model.SuccessResponse{
		Username: id[0],
		Message:  "delete success",
	}

	response, err := json.Marshal(success)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Internal Server Error"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response) // TODO: answer here
}

// DESC: Gunakan variable ini sebagai goroutine di handler GetWeather
var GetWetherByRegionAPI = client.GetWeatherByRegion

func GetWeather(w http.ResponseWriter, r *http.Request) {
	var listRegion = []string{"jakarta", "bandung", "surabaya", "yogyakarta", "medan", "makassar", "manado", "palembang", "semarang", "bali"}

	weatherChan := make(chan model.MainWeather)
	errorChan := make(chan error)

	// DESC: dapatkan data weather dari 10 data di atas menggunakan goroutine
	for _, region := range listRegion {
		go func(region string) {
			weather, err := GetWetherByRegionAPI(region)
			if err != nil {
				errorChan <- err
			} else {
				weatherChan <- weather
			}
		}(region)
	}

	weathers := make([]model.MainWeather, 0)
	for i := 0; i < len(listRegion); i++ {
		select {
		case weather := <-weatherChan:
			weathers = append(weathers, weather)
		case err := <-errorChan:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	jsonResponse, err := json.Marshal(weathers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse) // TODO: answer here
}
