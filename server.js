const cluster = require("cluster");
const http = require("http");
const express = require("express");
const firebase = require("firebase-admin");
const hpp = require('hpp');
const nodemailer = require("nodemailer");
const axios = require("axios");
const saltRounds = 12;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require('helmet');
const crypto = require('crypto');
const PAYSTACK_SECRET_KEY = 'sk_test_5b9abe0ffe65fc95907c056508e32a011ea7f439';
var request = require('request');


const app = express();
const port = process.env.PORT || 3000;

const server = http.createServer(app);

const firebaseServiceAccount = require("./spinz-a4867-firebase-adminsdk-mhswt-ab64a75658.json");

firebase.initializeApp({
  credential: firebase.credential.cert(firebaseServiceAccount),
  databaseURL: "https://spinz-a4867-default-rtdb.firebaseio.com",
});

const db = firebase.database();

app.use(express.json({ limit: '1mb' }));
app.use(helmet());

app.use(hpp());
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));

app.set('trust proxy', 'loopback');

const corsOptions = {
  origin: ['https://spinz-three.vercel.app', 'https://spinz-spin.vercel.app', 'https://spinz-three.vercel.app/'],
  credentials: true,
  exposedHeaders: ['Content-Length', 'X-Content-Type-Options', 'X-Frame-Options'],
};

app.use(cors(corsOptions));

const secretKey = process.env.secret_key || "DonaldMxolisiRSA04?????";

app.use((req, res, next) => {
  const allowedOrigins = ['https://spinz-three.vercel.app', 'https://spinz-three.vercel.app', 'https://spinz-three.vercel.app', 'https://spinz-three.vercel.app'];
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }

  res.header('Access-Control-Allow-Credentials', true);

  if (req.method === 'OPTIONS') {
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Access-Control-Allow-Origin', 'Content-Type, Authorization');
    return res.status(200).json({});
  }

  next();
});

const SendWithdrawalSmS = async (cellphone, bank, account, amount) => {
  var countryCode = '+27'
  const Phone = cellphone.replace("0", "")
  mobileNumber = Phone,
    message = `Spinz4bets: You have requested a withdrawal of R${amount} to ${bank} account no: ${account}. Withdrawals takes 24 hours to reflect.`;

  request.post({
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'Accepts': 'application/json'
    },
    url: process.env.BLOWERIO_URL + '/messages',
    form: {
      to: countryCode + mobileNumber,
      message: message
    }
  }, function (error, response, body) {
    if (!error && response.statusCode == 201) {
      console.log('Message sent!')
    } else {
      var apiResult = JSON.parse(body)
      console.log('Error was: ' + apiResult.message)
    }
  })
}



app.post("/signup", async (req, res) => {
  const { fullName, surname, cell, idNumber, password, country } = req.body;

  try {
    const numberId = generateRandomNumber();
    let fixedIdNumber = idNumber || numberId;
    let amount;

    const usAmount = "10.00";
    const saAmount = "10.00";

    if (country !== "ZA") {
      amount = usAmount;
    } else {
      amount = saAmount;
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(409).json({ error: "Invalid input. Please check your information." });
    }

    if (!fullName || !surname || !cell || !password || !country) {
      return res.status(409).json({ error: "All fields are required." });
    }

    const cellSnapshot = await db.ref('users').orderByChild('cell').equalTo(cell).once('value');
    if (cellSnapshot.exists()) {
      return res.status(201).json({ error: "Cell number already registered." });
    }

    const idNumberSnapshot = await db.ref('users').orderByChild('idNumber').equalTo(fixedIdNumber).once('value');
    if (idNumberSnapshot.exists()) {
      return res.status(208).json({ error: "ID number already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const userRef = db.ref('users').push();
    userRef.set({
      name: fullName,
      surname: surname,
      cell: cell,
      idNumber: fixedIdNumber,
      country: country,
      password: hashedPassword,
      balance: amount,
    });

    res.status(200).json({ message: "User created successfully." });
  } catch (err) {
    console.error("Error during signup:", err);
    return res.status(500).json({ error: "Internal server error. Please try again later." });
  }
});

const generateRandomNumber = () => {
  const randomNumber = Math.floor(Math.random() * 10000000000000).toString();
  return randomNumber.padStart(13, '0');
};


const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: "Too many login attempts from this IP, please try again later",
});


app.post('/pay', async (req, res) => {
  try {
    const { amount, email, token } = req.body;
    let decodedToken;
    try {
      decodedToken = jwt.verify(token, secretKey);
    } catch (tokenError) {
      console.error("Error verifying token:", tokenError);
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    const Phone = decodedToken.cell;
    const response = await axios.post('https://api.paystack.co/transaction/initialize', {
      amount: amount,
      email: email,
      phone: Phone,

    }, {
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`
      }
    });
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get("/balance", async (req, res) => {
  const token = req.header("Authorization");

  if (!token || !token.startsWith("Bearer ")) {
    return res.redirect(401, "https://spinz-three.vercel.app/");
  }


  const tokenValue = token.replace("Bearer ", "");

  try {
    const decodedToken = jwt.verify(tokenValue, secretKey);

    const snapshot = await db.ref('users').orderByChild('cell').equalTo(decodedToken.cell).once('value');
    const user = snapshot.val();



    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }


    const userBalance = user[Object.keys(user)[0]].balance;
    const country = user[Object.keys(user)[0]].country;

    return res.status(200).json({ balance: userBalance, country: country });
  } catch (err) {
    console.error("Error fetching user balance:", err);
    return res.status(500).json({ error: "Internal server error. Please try again later." });
  }
});

app.post("/dice", async (req, res) => {
  const gameUrl = 'https://dice-bytebeem.vercel.app/';


  const token = req.header("Authorization").replace("Bearer ", "");

  let decodedToken;
  try {
    decodedToken = jwt.verify(token, secretKey);
  } catch (tokenError) {
    console.error("Error verifying token:", tokenError);
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  const userId = decodedToken.cell;

  try {


    const gameId = generateUniqueId();


    const gamesPlayedRef = db.ref('gamesPlayed').push();
    gamesPlayedRef.set({
      cell: userId,
      activity_description: "Game",
      activity_details: `Game Dice  - Game ID: ${gameId}`,
      date_time: new Date(),
    });

    res.status(200).json({
      message: "Game started successfully. Redirecting...",
      gameLink: `${gameUrl}?gameId=${gameId}&token=${token}`,
    });
  } catch (insertError) {
    console.error("Error inserting activity record:", insertError);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/startGame", async (req, res) => {
  const { betAmount } = req.body;

  const gameServer = 'https://word-search-wine.vercel.app/';


  if (isNaN(parseFloat(betAmount)) || parseFloat(betAmount) <= 0) {
    return res.status(400).json({ error: "Invalid bet amount" });
  }


  const token = req.header("Authorization").replace("Bearer ", "");
  let decodedToken;
  try {
    decodedToken = jwt.verify(token, secretKey);
  } catch (tokenError) {
    console.error("Error verifying token:", tokenError);
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  const userId = decodedToken.cell;


  try {
    const snapshot = await db.ref('users').orderByChild('cell').equalTo(decodedToken.cell).once('value');
    const user = snapshot.val();

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const Userbalance = user[Object.keys(user)[0]].balance;


    if (betAmount > Userbalance) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const userKey = Object.keys(user)[0];
    const userRef = db.ref(`users/${userKey}`);


    const newBalance = Userbalance - parseFloat(betAmount);
    await userRef.update({ balance: newBalance });


    const gameId = generateUniqueId();

    const gamesPlayedRef = db.ref('gamesPlayed').push();
    gamesPlayedRef.set({
      cell: userId,
      activity_description: "Game",
      activity_details: `Game Word Search - R${betAmount} - Game ID: ${gameId}`,
      date_time: new Date(),
    });

    res.status(200).json({
      message: "Game started successfully. Redirecting...",
      gameLink: `${gameServer}?gameId=${gameId}`,
    });

  } catch (error) {
    console.error("Error fetching user data:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});




app.post("/slot", async (req, res) => {
  const gameUrl = 'https://spinz-spin.vercel.app/';


  const token = req.header("Authorization").replace("Bearer ", "");

  let decodedToken;
  try {
    decodedToken = jwt.verify(token, secretKey);
  } catch (tokenError) {
    console.error("Error verifying token:", tokenError);
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  const userId = decodedToken.cell;


  const gameId = generateUniqueId();

  try {
    const userRef = db.ref('gamesPlayed').push();
    userRef.set({
      cell: userId,
      activity_description: "Game",
      activity_details: `Game Slot Machine - Game ID: ${gameId}`,
      date_time: new Date(),
    });

    res.status(200).json({
      message: "Game started successfully. Redirecting...",
      gameLink: `${gameUrl}?gameId=${gameId}&token=${token}`,
    });
  } catch (insertError) {
    console.error("Error inserting activity record:", insertError);
    res.status(500).json({ error: "Database error" });
  }
});



function generateUniqueId() {
  const randomBytes = crypto.randomBytes(16);
  const hash = crypto.createHash('sha256').update(randomBytes).digest('hex');
  return hash;
}


app.get("/getUserData", async (req, res) => {
  const token = req.header("Authorization");

  if (!token || !token.startsWith("Bearer ")) {
    return res.redirect(401, "https://spinz-three.vercel.app/");
  }


  const tokenValue = token.replace("Bearer ", "");

  try {
    const decodedToken = jwt.verify(tokenValue, secretKey);

    const snapshot = await db.ref('users').orderByChild('cell').equalTo(decodedToken.cell).once('value');
    const user = snapshot.val();


    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }


    const name = user[Object.keys(user)[0]].name;
    const surname = user[Object.keys(user)[0]].surname;
    const cell = user[Object.keys(user)[0]].cell;
    const balance = user[Object.keys(user)[0]].balance;

    return res.status(200).json({ name: name, cell: cell, surname: surname, balance: balance });
  } catch (err) {
    console.error("Error fetching user info:", err);
    return res.status(500).json({ error: "Internal server error. Please try again later." });
  }
});


function sendDepositConfirmationEmail(userId, amount) {
  const transporter = nodemailer.createTransport({

    service: 'Gmail',
    auth: {
      user: 'heckyl66@gmail.com',
      pass: 'izpanbvcuqhsvlyb',
    },
  });

  const mailOptions = {
    from: "heckyl66@gmail.com",
    to: "donald.mxolisi@proton.me",
    subject: "Deposit Confirmation",
    html: `
      <p>Deposit Confirmation Details:</p>
      <ul>
        <li>User ID: ${userId}</li>
        <li>Deposit Amount: ${amount}</li>
      </ul>
      <p>Your deposit request is being processed. Thank you!</p>
    `,
  };

  transporter.sendMail(mailOptions, (emailError, info) => {
    if (emailError) {
      console.error("Error sending email:", emailError);

    } else {
      console.log("Email sent: " + info.response);

    }
  });
}

app.post("/spinzbetswebhook/webhookV1/url", async function (req, res) {

  const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(JSON.stringify(req.body)).digest('hex');
  if (hash == req.headers['x-paystack-signature']) {

    const event = req.body;
    if (event.event === 'charge.success') {
      if (event.data.status === 'success') {
        let amountMade = parseFloat(event.data.amount / 100);
        const snapshot = await db.ref('users').orderByChild('cell').equalTo(event.data.customer.phone).once('value');
        const user = snapshot.val();
        const Userbalance = user[Object.keys(user)[0]].balance;

        const userKey = Object.keys(user)[0];
        const userUpdate = db.ref(`users/${userKey}`);

        const newBalance = parseFloat(Userbalance + amountMade);
        await userUpdate.update({ balance: newBalance });
        const userRef = db.ref('deposits').push();
        userRef.set({
          user: event.data,

        });

        sendDepositConfirmationEmail(event.data.customer.email, amountMade);

      } else {
        res.send(400);
      }

    } else {
      res.send(401);
    }

  }
  res.send(200);
});

app.post('/withdraw', async (req, res) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');
    const { amount, Account, bank, password } = req.body;

    if (!bank) {
      return res.status(400).json({ error: 'Select your Bank' });
    }

    const decodedToken = jwt.verify(token, secretKey);
    const userId = decodedToken.cell;

    const snapshot = await db.ref('users').orderByChild('cell').equalTo(decodedToken.cell).once('value');
    const user = snapshot.val();



    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const Username = user[Object.keys(user)[0]].name;
    const Usersurname = user[Object.keys(user)[0]].surname;
    const Usercell = user[Object.keys(user)[0]].cell;
    const Userpassword = user[Object.keys(user)[0]].password;
    const Userbalance = user[Object.keys(user)[0]].balance;
    const userCountry = user[Object.keys(user)[0]].country;


    const isMatch = await bcrypt.compare(password, Userpassword);

    if (!isMatch) {
      return res.status(400).json({ error: 'Incorrect Password' });
    }


    if (isNaN(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Invalid withdrawal amount' });
    }

    if (amount < 200 && userCountry === "ZA") {
      return res.status(400).json({ error: 'Minimum withdrawal amount is R200' });
    }

    if (amount < 200 && userCountry !== "ZA") {
      return res.status(400).json({ error: 'Minimum withdrawal amount is $100' });
    }


    if (amount > Userbalance) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const userKey = Object.keys(user)[0];
    const userRef = db.ref(`users/${userKey}`);

    const newBalance = Userbalance - amount;
    await userRef.update({ balance: newBalance });


    const withdrawalRef = db.ref('withdrawals').push();
    withdrawalRef.set({
      user_id: userId,
      activity_description: 'Withdrawal',
      activity_details: `Withdrawal of R${amount} to Account No: ${Account}, Bank: ${bank}`,
      date_time: new Date().toISOString(),
    });

    const transporter = nodemailer.createTransport({

      service: 'Gmail',
      auth: {
        user: 'heckyl66@gmail.com',
        pass: 'wvzqobuvijaribkb',
      },
    });


    const mailOptions = {
      from: 'heckyl66@gmail.com',
      to: 'spinz.spin@proton.me',
      subject: 'Withdrawal Request',
      html: `
        <p>Withdrawal Request Details:</p>
        <ul>
          <li>Name: ${Username}</li>
          <li>SurName: ${Usersurname}</li>
          <li>Cell: ${Usercell}</li>
          <li>User ID: ${userId}</li>
          <li>Withdrawal Amount: ${amount}</li>
          <li>Account: ${Account}</li>
          <li>Bank: ${bank}</li>
        </ul>
        <p>Your withdrawal request is being processed. Thank you!</p>
      `,
    };


    await transporter.sendMail(mailOptions);
    SendWithdrawalSmS(Usercell, bank, Account, amount);

    res.status(200).json({ message: 'Withdrawal successful', newBalance });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.post("/login", loginLimiter, async (req, res) => {
  const { cell, password, token } = req.body;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: "Invalid input. Please check your data." });
  }

  try {
    if (token) {
      let decodedToken;
      try {
        decodedToken = jwt.verify(token, secretKey);
      } catch (err) {

      }

      
      const snapshot = await db.ref('users').orderByChild('cell').equalTo(cell).once('value');
      const userData = snapshot.val();

      if (!userData) {
        return res.status(401).json({ error: "User not found." });
      }

      const user = Object.values(userData)[0];

      if (!user) {
        return res.status(401).json({ error: "User not found." });
      }

      const newToken = jwt.sign(
        {
          userId: user.id,
          id: user.id,
          name: user.name,
          cell: user.cell,
          balance: user.balance,
          surname: user.surname,
        },
        secretKey,
        { expiresIn: "7D" }
      );

      return res.status(200).json({ token: newToken });
    } else {
      const snapshot = await db.ref('users').orderByChild('cell').equalTo(cell).once('value');
      const userData = snapshot.val();

      if (!userData) {
        return res.status(201).json({ error: "User not found." });
      }

      const userValues = Object.values(userData);

      if (!userValues || userValues.length === 0) {
        return res.status(401).json({ error: "User not found." });
      }

      const user = userValues[0];

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(202).json({ error: "Incorrect password." });
      }

      const newToken = jwt.sign(
        {
          userId: user.id,
          id: user.id,
          name: user.name,
          cell: user.cell,
          balance: user.balance,
          surname: user.surname,
        },
        secretKey,
        { expiresIn: "7D" }
      );



      res.status(200).json({ token: newToken });

    }
  } catch (err) {
    console.error("Error during login:", err);
    return res.status(500).json({ error: "Internal server error. Please try again later." });
  }
});



if (cluster.isMaster) {
  const numCPUs = require("os").cpus().length;
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on("exit", (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died`);
  });
} else {
  server.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
}
