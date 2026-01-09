package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	TGMaxTextLength = 4096
)

type Config struct {
	Log struct {
		Level string `yaml:"level"`
		Path  string `yaml:"path"`
	} `yaml:"log"`
	Telegram struct {
		BotToken string `yaml:"bot_token"`
		ChatID   string `yaml:"chat_id"`
	} `yaml:"telegram"`
}

var (
	config Config
	logger *log.Logger
)

func init() {
	// Try to load config from multiple locations
	configPaths := []string{
		"sendmail.yaml",
		"/etc/tg-sendmail.yaml",
		"/etc/sendmail.yaml",
	}

	var configFound bool
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			if err := loadConfig(path); err == nil {
				configFound = true
				break
			}
		}
	}

	if !configFound {
		fmt.Fprintln(os.Stderr, "Cannot find configuration file")
		os.Exit(1)
	}

	// Setup logging
	logFile, err := os.OpenFile(config.Log.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	logger = log.New(logFile, "", log.LstdFlags)
}

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, &config)
}

func getUpdates(token string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates", token)
	resp, err := http.Get(url)
	if err != nil {
		logger.Printf("get updates error. URL: %s Error: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Printf("get updates read error: %v\n", err)
		return
	}

	logger.Printf("get updates response: %s\n", string(body))

	var result struct {
		Ok     bool `json:"ok"`
		Result []struct {
			Message struct {
				Chat struct {
					ID       int64  `json:"id"`
					Username string `json:"username"`
				} `json:"chat"`
			} `json:"message"`
		} `json:"result"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		logger.Printf("get updates json decode error: %v\n", err)
		return
	}

	if !result.Ok {
		logger.Println("get updates response is not ok")
		return
	}

	if len(result.Result) == 0 {
		warningMessage := "No updates. Try to send some messages to the bot"
		logger.Println(warningMessage)
		fmt.Print(warningMessage)
		return
	}

	for _, update := range result.Result {
		chatID := update.Message.Chat.ID
		username := update.Message.Chat.Username
		logString := fmt.Sprintf("Chat Id: %d. Username: %s", chatID, username)
		logger.Printf("get updates data: %s\n", logString)
		fmt.Print(logString)
	}
}

func generateFullName(fullName, address string) string {
	if fullName != "" {
		return fmt.Sprintf("%s <%s>", fullName, address)
	}
	return address
}

func prepareEmail(senderName, senderAddress string, remains []string, parseToHeader bool) (*mail.Message, error) {
	msg, err := mail.ReadMessage(os.Stdin)
	if err != nil {
		return nil, err
	}

	if !parseToHeader && msg.Header.Get("To") == "" && len(remains) > 0 {
		for _, arg := range remains {
			addr, err := mail.ParseAddress(arg)
			if err != nil {
				// If parsing fails, use as-is
				msg.Header["To"] = append(msg.Header["To"], arg)
			} else {
				msg.Header["To"] = append(msg.Header["To"], generateFullName(addr.Name, addr.Address))
			}
		}
	}

	if msg.Header.Get("From") == "" && senderAddress != "" {
		msg.Header["From"] = []string{generateFullName(senderName, senderAddress)}
	}

	return msg, nil
}

func generateMessage(msg *mail.Message) (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	var message strings.Builder
	message.WriteString(fmt.Sprintf("Node: <b>%s</b>\n\n", html.EscapeString(hostname)))

	for key, values := range msg.Header {
		for _, value := range values {
			message.WriteString(fmt.Sprintf("<i>%s:</i> <b>%s</b>\n",
				html.EscapeString(key), html.EscapeString(value)))
		}
	}

	message.WriteString("\n")

	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return "", err
	}

	message.WriteString(fmt.Sprintf("<pre>%s</pre>", html.EscapeString(string(body))))

	return message.String(), nil
}

func send(message, token, chatID string) error {
	longMessage := ""
	if len(message) > TGMaxTextLength {
		longMessage = message
		message = message[:500] + "\n\n<b>Message is too long. See attached file below</b>"
	}

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       message,
		"parse_mode": "HTML",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	logger.Printf("Send payload: %s\n", string(jsonData))

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	logger.Printf("Response: %s\n", string(respBody))

	if longMessage != "" {
		return sendFile("long_message.txt", []byte(longMessage), token, chatID)
	}

	return nil
}

func sendFile(filepath string, content []byte, token, chatID string) error {
	body, contentType := encodeMultipartFormdata(filepath, content)

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument?chat_id=%s", token, chatID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", contentType)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	logger.Printf("Response: %s\n", string(respBody))

	return nil
}

func readContent(filepath string) ([]byte, error) {
	return os.ReadFile(filepath)
}

func getContentType(filepath string) string {
	mimeType := mime.TypeByExtension(filepath)
	if mimeType == "" {
		return "application/octet-stream"
	}
	return mimeType
}

func encodeMultipartFormdata(filepath string, content []byte) ([]byte, string) {
	boundary := "boundary"
	var buf bytes.Buffer

	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"document\"; filename=\"%s\"\r\n",
		filepath))
	buf.WriteString(fmt.Sprintf("Content-Type: %s\r\n", getContentType(filepath)))
	buf.WriteString("\r\n")
	buf.Write(content)
	buf.WriteString("\r\n")
	buf.WriteString("--" + boundary + "--")

	return buf.Bytes(), fmt.Sprintf("multipart/form-data; boundary=%s", boundary)
}

func main() {
	// Define flags
	sendFileFlag := flag.String("send-file", "", "Send local file to the telegram bot")
	getUpdatesFlag := flag.Bool("get-updates", false, "Run getUpdates method with bot token to achieve chat_id")
	senderFullName := flag.String("F", "", "Set the full name of the sender.")
	senderAddress := flag.String("f", "", "Sets the name of the 'from' person (i.e., the envelope sender of the mail).")
	parseToHeader := flag.Bool("t", false, "Read message for recipients.")
	
	// Parse known flags and collect remaining args
	flag.Parse()
	remains := flag.Args()

	// Handle -oi flag (ignore single dot on line) - standard sendmail compatibility
	// Just consume it silently for compatibility
	for i, arg := range os.Args[1:] {
		if arg == "-oi" {
			// Remove from remains if present
			newRemains := []string{}
			for j, r := range remains {
				if j != i {
					newRemains = append(newRemains, r)
				}
			}
			remains = newRemains
			break
		}
	}

	chatID := config.Telegram.ChatID
	botToken := config.Telegram.BotToken
	validCredentials := chatID != "" && botToken != ""

	if *getUpdatesFlag {
		getUpdates(botToken)
		return
	}

	if *sendFileFlag != "" {
		if _, err := os.Stat(*sendFileFlag); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "File %s does not exist!\n", *sendFileFlag)
			os.Exit(1)
		}
		if !validCredentials {
			logger.Println("Please fill /etc/tg-sendmail.ini configuration file!")
			os.Exit(1)
		}
		content, err := readContent(*sendFileFlag)
		if err != nil {
			logger.Printf("Error reading file: %v\n", err)
			os.Exit(1)
		}
		if err := sendFile(filepath.Base(*sendFileFlag), content, botToken, chatID); err != nil {
			logger.Printf("Error sending file: %v\n", err)
			os.Exit(1)
		}
		return
	}

	email, err := prepareEmail(*senderFullName, *senderAddress, remains, *parseToHeader)
	if err != nil {
		logger.Printf("Error preparing email: %v\n", err)
		os.Exit(1)
	}

	logger.Printf("Prepared email with headers: %v\n", email.Header)

	message, err := generateMessage(email)
	if err != nil {
		logger.Printf("Error generating message: %v\n", err)
		os.Exit(1)
	}

	logger.Printf("Prepared message: %s\n", message)

	if !validCredentials {
		logger.Println("Please fill /etc/tg-sendmail.ini configuration file!")
		os.Exit(1)
	}

	if err := send(message, botToken, chatID); err != nil {
		logger.Printf("Error sending message: %v\n", err)
		os.Exit(1)
	}
}
