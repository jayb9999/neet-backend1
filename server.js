// Backend (Node.js + Express)
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
//const Database = require("better-sqlite3");
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken')
//const bcrypt = require('bcrypt');
//const bcrypt = require("bcryptjs");
//const cookieParser = require("cookie-parser");
//require("dotenv").config()

const app = express();
const MY_SECRET_TOKEN = process.env.JWT_SECRET || "defaultsecret";
const PORT = process.env.PORT || 5000;

app.use(express.json())
//app.use(cookieParser())
app.use(bodyParser.json());
app.use(cors());

// Database setup
const db = new sqlite3.Database('./neetexam.db', (err) => {
    if (err) console.error('Database opening error:', err);
    console.log('Connected to SQLite database.');
  });

// Create tables
const createTables = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  no_of_questions INTEGER NOT NULL,
  time INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  test_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  question TEXT NOT NULL,
  image_url TEXT,
  options TEXT,
  correct_answer TEXT NOT NULL,
  FOREIGN KEY (test_id) REFERENCES tests(id)
);

CREATE TABLE IF NOT EXISTS student_answers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  question_id INTEGER NOT NULL,
  answer TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (question_id) REFERENCES questions(id)
);
`;

db.exec(createTables);

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  
  // Check if the Authorization header exists and starts with 'Bearer'
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send("Invalid JWT Token");
  }
  
  // Extract the token from the 'Bearer <token>' format
  const jwtToken = authHeader.split(" ")[1];
  
  // Verify the token using the jwt.verify method
  jwt.verify(jwtToken, MY_SECRET_TOKEN, (error, payload) => {
    if (error) {
      return res.status(401).send("Invalid JWT Token");
    } else {
      req.username = payload.username; // Add payload to request object
      next(); // Proceed to the next middleware or route handler
    }
  });
};


// Authentication routes
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if the fields are present
  if (!username || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  // Hash the password
  //const hashedPassword = await bcrypt.hash(password, 10);

  // Check if the user already exists
  const checkUserQry = `SELECT * FROM users WHERE username = ?`;
  const dbUser = await new Promise((resolve, reject) => {
    db.get(checkUserQry, [username], (err, row) => {
      if (err) reject(err);
      resolve(row);
    });
  });

  if (dbUser) {
    // If user already exists, send error
    return res.status(400).json({ error: "User already exists" });
  }

  // Insert the new user into the database
  const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
  db.run(query, [username, password], (err) => {
    if (err) {
      return res.status(400).send({ error: err.message });
    }
    // Respond with success
    res.send({ message: `User registered successfully with username: ${username}` });
  });
});


app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  // Query to check if user exists (using parameterized query to avoid SQL injection)
  const qry = 'SELECT * FROM users WHERE username = ?';
  const dbUser = await new Promise((resolve, reject) => {
    db.get(qry, [username], (err, row) => {
      if (err) reject(err);
      resolve(row);
    });
  });

  // Debugging: log the password from the request and the database
  // console.log('Password from request body:', password);
  // console.log('Password from database:', dbUser.password);
  // console.log(dbUser)

  if (dbUser === undefined) {
    return res.status(400).send("Invalid User");
  } else {
    // Check if the password in the database exists
    if (!dbUser.password) {
      return res.status(500).send("Database error: No password found for the user");
    }

    // Compare the plain password with the hashed password stored in the DB
    try {
      const isPasswordMatched = password //await bcrypt.compare(password, dbUser.password);

      if (isPasswordMatched) {
        // Generate JWT token
        const payload = { username: username };
        const jwtToken = jwt.sign(payload, MY_SECRET_TOKEN, { expiresIn: "1h" });
        res.send({ jwtToken });
      } else {
        res.status(400).send("Invalid Password");
      }
    } catch (err) {
      console.error('Error comparing passwords:', err);
      res.status(500).send('Error during password comparison');
    }
  }
});


app.get('/api/questions', authenticateToken, (req, res) => {
  const query = `SELECT * FROM questions`;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(400).send({ error: err.message });
    //const data = JSON.parse(rows)
    //console.log(rows)
    res.send(rows);
  });
});

app.post('/tests', authenticateToken, (req, res) => {
  const { title } = req.body;
  const query = `INSERT INTO tests (title) VALUES (${title})`;
  db.run(query, [title], err => {
    if (err) return res.status(400).send({ error: err.message });
    res.send({ id: this.lastID, title });
  });
});

app.post('/question', authenticateToken, (req, res) => {
  const { test_id, question, image, type, options, correct_answer } = req.body;
  const query = `INSERT INTO questions (test_id, question, image, type, options, correct_answer) VALUES (${test_id}, ${question}, ${image}, ${type}, ${options}, ${correct_answer})`;
  db.run(query, [test_id, question, image, type, options, correct_answer], (err) => {
    if (err) return res.status(400).send({ error: err.message });
    res.send({ id: this.lastID });
  });
});

// Student routes
app.get('/tests', (req, res) => {
  const query = `SELECT * FROM tests`;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).send({ error: err.message });
    res.send(rows);
  });
});

app.get('/test/:test_id', (req, res) => {
  const { test_id } = req.params;
  const query = `SELECT * FROM questions WHERE test_id = ${test_id}`;
  db.all(query, [test_id], (err, rows) => {
    if (err) return res.status(500).send({ error: err.message });
    res.send(rows);
  });
});

app.post('/answers', (req, res) => {
  const { user_id, question_id, answer } = req.body;
  const query = `INSERT INTO student_answers (user_id, question_id, answer) VALUES (?, ?, ?)`;
  db.run(query, [user_id, question_id, answer], function (err) {
    if (err) return res.status(400).send({ error: err.message });
    res.send({ id: this.lastID });
  });
});

app.get('/results/:user_id/:test_id', (req, res) => {
  const { user_id, test_id } = req.params;
  const query = `
    SELECT q.id AS question_id, q.correct_answer, a.answer
    FROM questions q
    LEFT JOIN student_answers a ON q.id = a.question_id AND a.user_id = ?
    WHERE q.test_id = ?
  `;
  db.all(query, [user_id, test_id], (err, rows) => {
    if (err) return res.status(500).send({ error: err.message });

    let score = 0;
    rows.forEach((row) => {
      if (row.answer === row.correct_answer) score++;
    });
    res.send({ score, total: rows.length, details: rows });
  });
});

// Server setup
app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
});