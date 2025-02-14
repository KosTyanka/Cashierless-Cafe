package main

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "html/template"
    "log"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/jung-kurt/gofpdf"
)

type TransactionPayload struct {
    CartItems []struct {
        ID       string  `json:"id"`
        Name     string  `json:"name"`
        Price    float64 `json:"price"`
        Quantity int     `json:"quantity"`
    } `json:"cartItems"`
    Customer struct {
        ID    string `json:"id"`
        Name  string `json:"name"`
        Email string `json:"email"`
    } `json:"customer"`
    TransactionID int `json:"transactionId"`
}

type MicroserviceResponse struct {
    PaymentURL     string `json:"paymentURL"`
    PaymentSuccess bool   `json:"paymentSuccess"`
    Status         string `json:"status"`
    Receipt        string `json:"receipt"`
}

type PaymentResult struct {
    PaymentSuccess bool   `json:"paymentSuccess"`
    Status         string `json:"status"`
    Receipt        string `json:"receipt"`
}

var transactionStore = make(map[int]TransactionPayload)

func addCORSHeaders(w http.ResponseWriter) {
    w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
    w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

// handleTransactions accepts a POSTed TransactionPayload and returns a JSON object with a payment URL.
func handleTransactions(w http.ResponseWriter, r *http.Request) {
    addCORSHeaders(w)
    if r.Method == http.MethodOptions {
        return
    }
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
        return
    }
    var payload TransactionPayload
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    transactionStore[payload.TransactionID] = payload
    paymentURL := fmt.Sprintf("http://localhost:8081/payment?tid=%d", payload.TransactionID)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "paymentURL": paymentURL,
    })
}

// handlePaymentForm serves an HTML form for entering payment details.
func handlePaymentForm(w http.ResponseWriter, r *http.Request) {
    addCORSHeaders(w)
    if r.Method == http.MethodOptions {
        return
    }
    tidStr := r.URL.Query().Get("tid")
    if tidStr == "" {
        http.Error(w, "Missing transaction ID", http.StatusBadRequest)
        return
    }
    tid, err := strconv.Atoi(tidStr)
    if err != nil {
        http.Error(w, "Invalid transaction ID", http.StatusBadRequest)
        return
    }
    if _, ok := transactionStore[tid]; !ok {
        http.Error(w, "Transaction not found", http.StatusNotFound)
        return
    }
    const tmplStr = `
<!DOCTYPE html>
<html>
<head>
  <title>Payment Form</title>
</head>
<body>
  <h1>Payment Form</h1>
  <form action="/processPayment?tid={{.TransactionID}}" method="POST">
    <label>Card Number:</label>
    <input type="text" name="cardNumber" required><br>
    <label>Expiration Date (MM/YY):</label>
    <input type="text" name="expirationDate" required><br>
    <label>CVV:</label>
    <input type="text" name="cvv" required><br>
    <label>Name on Card:</label>
    <input type="text" name="name" required><br>
    <label>Billing Address:</label>
    <input type="text" name="address" required><br>
    <button type="submit">Submit Payment</button>
  </form>
</body>
</html>
`
    t, err := template.New("paymentForm").Parse(tmplStr)
    if err != nil {
        http.Error(w, "Template error", http.StatusInternalServerError)
        return
    }
    data := struct {
        TransactionID int
    }{
        TransactionID: tid,
    }
    w.Header().Set("Content-Type", "text/html")
    t.Execute(w, data)
}

// handleProcessPayment processes the submitted payment form,
// generates a PDF receipt, and returns an HTML page that triggers the download then redirects.
func handleProcessPayment(w http.ResponseWriter, r *http.Request) {
    addCORSHeaders(w)
    if r.Method == http.MethodOptions {
        return
    }
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
        return
    }
    tidStr := r.URL.Query().Get("tid")
    if tidStr == "" {
        http.Error(w, "Missing transaction ID", http.StatusBadRequest)
        return
    }
    tid, err := strconv.Atoi(tidStr)
    if err != nil {
        http.Error(w, "Invalid transaction ID", http.StatusBadRequest)
        return
    }
    transaction, ok := transactionStore[tid]
    if !ok {
        http.Error(w, "Transaction not found", http.StatusNotFound)
        return
    }
    if err := r.ParseForm(); err != nil {
        http.Error(w, "Failed to parse form", http.StatusBadRequest)
        return
    }
    cardNumber := r.FormValue("cardNumber")
    expirationDate := r.FormValue("expirationDate")
    _ = r.FormValue("cvv") // CVV is not used in this demo.
    paymentName := r.FormValue("name")
    address := r.FormValue("address")

    // For testing: if the card number starts with "1234", payment succeeds.
    paymentSuccess := strings.HasPrefix(cardNumber, "1234")
    status := "Declined"
    if paymentSuccess {
        status = "Paid"
    }
    totalAmount := 0.0
    for _, item := range transaction.CartItems {
        totalAmount += item.Price * float64(item.Quantity)
    }

    // Generate PDF receipt.
    pdf := gofpdf.New("P", "mm", "A4", "")
    pdf.AddPage()
    pdf.SetFont("Arial", "B", 16)
    pdf.Cell(40, 10, "Cashierless Cafe")
    pdf.Ln(12)
    pdf.SetFont("Arial", "", 12)
    pdf.Cell(40, 10, fmt.Sprintf("Transaction ID: %d", transaction.TransactionID))
    pdf.Ln(8)
    pdf.Cell(40, 10, fmt.Sprintf("Order Date: %s", time.Now().Format("02 Jan 2006 15:04:05")))
    pdf.Ln(8)
    pdf.Cell(40, 10, fmt.Sprintf("Customer: %s", transaction.Customer.Name))
    pdf.Ln(12)
    pdf.SetFont("Arial", "B", 12)
    pdf.CellFormat(60, 7, "Product", "1", 0, "C", false, 0, "")
    pdf.CellFormat(30, 7, "Price", "1", 0, "C", false, 0, "")
    pdf.CellFormat(30, 7, "Quantity", "1", 0, "C", false, 0, "")
    pdf.CellFormat(40, 7, "Line Total", "1", 0, "C", false, 0, "")
    pdf.Ln(-1)
    pdf.SetFont("Arial", "", 12)
    for _, item := range transaction.CartItems {
        lineTotal := item.Price * float64(item.Quantity)
        pdf.CellFormat(60, 7, item.Name, "1", 0, "", false, 0, "")
        pdf.CellFormat(30, 7, fmt.Sprintf("$%.2f", item.Price), "1", 0, "R", false, 0, "")
        pdf.CellFormat(30, 7, fmt.Sprintf("%d", item.Quantity), "1", 0, "C", false, 0, "")
        pdf.CellFormat(40, 7, fmt.Sprintf("$%.2f", lineTotal), "1", 0, "R", false, 0, "")
        pdf.Ln(-1)
    }
    pdf.Ln(4)
    pdf.SetFont("Arial", "B", 12)
    pdf.CellFormat(120, 7, "Total Amount", "1", 0, "R", false, 0, "")
    pdf.CellFormat(40, 7, fmt.Sprintf("$%.2f", totalAmount), "1", 0, "R", false, 0, "")
    pdf.Ln(10)
    pdf.SetFont("Arial", "", 12)
    paymentDetails := fmt.Sprintf("Payment Method: Credit Card ending in %s", cardNumber[len(cardNumber)-4:])
    pdf.Cell(40, 10, paymentDetails)
    pdf.Ln(8)
    pdf.Cell(40, 10, "Encrypted Card Details: ************")
    pdf.Ln(8)
    pdf.Cell(40, 10, fmt.Sprintf("Expiration Date: %s", expirationDate))
    pdf.Ln(8)
    pdf.Cell(40, 10, fmt.Sprintf("Cardholder Name: %s", paymentName))
    pdf.Ln(8)
    pdf.Cell(40, 10, fmt.Sprintf("Billing Address: %s", address))
    pdf.Ln(10)
    var pdfBuffer bytes.Buffer
    if err := pdf.Output(&pdfBuffer); err != nil {
        http.Error(w, "Failed to generate PDF", http.StatusInternalServerError)
        return
    }
    encodedPDF := base64.StdEncoding.EncodeToString(pdfBuffer.Bytes())

    // Render an HTML page that automatically triggers the download and then redirects.
    const resultTemplate = `
<!DOCTYPE html>
<html>
<head>
  <title>Payment Result</title>
  <script>
    function triggerDownloadAndRedirect() {
      var link = document.createElement('a');
      link.href = 'data:application/pdf;base64,{{.Receipt}}';
      link.download = 'receipt.pdf';
      document.body.appendChild(link);
      link.click();
      setTimeout(function(){
        window.location.href = 'http://localhost:8080/index';
      }, 3000);
    }
    window.onload = triggerDownloadAndRedirect;
  </script>
</head>
<body>
  <h1>Payment {{.Status}}</h1>
  <p>Your payment was {{.Status}}. Your receipt will download automatically. If not, <a href="data:application/pdf;base64,{{.Receipt}}" download="receipt.pdf">click here</a>.</p>
</body>
</html>
`
    data := struct {
        Status  string
        Receipt string
    }{
        Status:  status,
        Receipt: encodedPDF,
    }
    w.Header().Set("Content-Type", "text/html")
    tmpl, err := template.New("result").Parse(resultTemplate)
    if err != nil {
        http.Error(w, "Template error", http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, data)
}

func main() {
    mux := http.NewServeMux()
    // Register endpoints wrapped with CORS headers (only once per pattern).
    mux.HandleFunc("/transactions", addCORS(handleTransactions))
    mux.HandleFunc("/payment", addCORS(handlePaymentForm))
    mux.HandleFunc("/processPayment", addCORS(handleProcessPayment))
    log.Println("Microservice running on port 8081...")
    log.Fatal(http.ListenAndServe(":8081", mux))
}

func addCORS(h http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        addCORSHeaders(w)
        h(w, r)
    }
}
