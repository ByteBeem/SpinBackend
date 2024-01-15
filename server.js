const cluster = require("cluster");
const http = require("http");
const express = require("express");
const bodyParser = require("body-parser");
const firebase = require("firebase-admin");
const csrf = require("csurf");
const csrfProtection = csrf({ cookie: true });
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
const { Server } = require('socket.io');
const randomColor = require('randomcolor');
const paypal = require('paypal-rest-sdk');

paypal.configure({
  mode: 'live',
  client_id: 'AVjPDrA3oq281bWnTyJpgeZjwuaLwnh-15lEg6wN0kbtI7SaUNbVTFdyQhX42PYDY_Vj8MqmXVFuPNaI',
  client_secret: 'EOoWPavFrbu50oMtCYfFWAk-UhDL_kow_nT3go8nc4tA_UWS71HF0eyilsf9CHhxJV1DIXgDAFQ6QRpV',
});


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


// Signup endpoint
app.post("/signup", async (req, res) => {
  const { fullName, surname, cell, idNumber, password, country } = req.body;

  try {
    const numberId = "1234567891234";
    let fixedIdNumber = idNumber || numberId;

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
      balance: 25.0,
    });

    res.status(200).json({ message: "User created successfully." });
  } catch (err) {
    console.error("Error during signup:", err);
    return res.status(500).json({ error: "Internal server error. Please try again later." });
  }
});



const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: "Too many login attempts from this IP, please try again later",
});

app.get("/balance", async (req, res) => {
  const token = req.header("Authorization");

  if (!token || !token.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized. Token not provided." });
  }

  const tokenValue = token.replace("Bearer ", "");

  try {
    const decodedToken = jwt.verify(tokenValue, secretKey);

    const snapshot = await db.ref('users').orderByChild('cell').equalTo(decodedToken.cell).once('value');
    const user = snapshot.val();

    console.log("Snapshot:", snapshot.val());

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }


     const userBalance = user[Object.keys(user)[0]].balance.toFixed(2);
    const country = user[Object.keys(user)[0]].country;

    return res.status(200).json({ balance: userBalance , country: country }); 
  } catch (err) {
    console.error("Error fetching user balance:", err);
    return res.status(500).json({ error: "Internal server error. Please try again later." });
  }
});

app.post('/depositPaypal', async (req, res) => {
  try {
    const { amount } = req.body;
    const amountValue = parseFloat(amount);

    const token = req.header('Authorization').replace('Bearer ', '');
    const decodedToken = jwt.verify(token, secretKey);
    const userId = decodedToken.cell;

    const paymentData = {
      intent: 'sale',
      payer: {
        payment_method: 'paypal',
      },
      transactions: [
        {
          amount: {
            total: amountValue.toFixed(2), // Ensure two decimal places
            currency: 'USD', // Update to your desired currency code
          },
        },
      ],
      redirect_urls: {
        return_url: 'https://spinz-three.vercel.app/profile',
        cancel_url: 'https://spinz-three.vercel.app/dashboard',
      },
    };

    paypal.payment.create(paymentData, (error, payment) => {
      if (error) {
        console.error(error.response);
        throw error;
      } else {
        // Redirect the user to the PayPal payment approval URL
        const redirectUrl = payment.links.find(link => link.rel === 'approval_url').href;

        // Save payment details to your database
        const paymentId = payment.id;
        const userRef = db.ref('deposits').push();
        userRef.set({
          cell: userId,
          payment_id: paymentId,
          amount: amountValue,
        });

        res.status(200).send({
          success: true,
          redirectUrl: redirectUrl,
        });
      }
    });
  } catch (error) {
    console.error('Payment initiation failed:', error);
    res.status(500).send({
      success: false,
      error: 'Payment initiation failed. Internal server error.',
    });
  }
});

app.get("/getUserData", async (req, res) => {
  const token = req.header("Authorization");

  if (!token || !token.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized. Token not provided." });
  }

  const tokenValue = token.replace("Bearer ", "");

  try {
    const decodedToken = jwt.verify(tokenValue, secretKey);

    const snapshot = await db.ref('users').orderByChild('cell').equalTo(decodedToken.cell).once('value');
    const user = snapshot.val();

    console.log("Snapshot:", snapshot.val());

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }


     const name = user[Object.keys(user)[0]].name;
    const surname = user[Object.keys(user)[0]].surname;
    const cell = user[Object.keys(user)[0]].cell;

    return res.status(200).json({ name: name  , cell: cell  , surname: surname  }); 
  } catch (err) {
    console.error("Error fetching user info:", err);
    return res.status(500).json({ error: "Internal server error. Please try again later." });
  }
});

app.post('/deposit', async (req, res) => {
  try {
    
    const { amount } = req.body;
    const amountValue = parseFloat(amount) * 100;
    
    const token = req.header('Authorization').replace('Bearer ', '');
    const paymentData = {
      amount: amountValue,
      currency: 'ZAR',
      cancelUrl: 'https://spinz-three.vercel.app/deposit',
      successUrl: 'https://spinz-three.vercel.app/profile',
      failureUrl: 'https://spinz-three.vercel.app/dashboard',
    };

    const paymentUrl = 'https://payments.yoco.com/api/checkouts/';

    const decodedToken = jwt.verify(token, secretKey);
    const userId = decodedToken.cell;

    const payfastResponse = await axios.post(paymentUrl, paymentData, {
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer sk_live_15431d914BDxBGa7af8461190a33',
      },
    });

    if (payfastResponse.status === 200) {
      const { redirectUrl, data } = payfastResponse.data;

      sendDepositConfirmationEmail(userId, amount);

      const paymentId = payfastResponse.data.id;


      const userRef = db.ref('deposits').push();
    userRef.set({
        cell: userId,
        payment_id: paymentId,
        amount: amountValue / 100,
    });

      res.status(200).send({
        success: true,
        redirectUrl: redirectUrl,
      });
    } else {
      console.error(
        'Payment initiation failed. PayFast returned:',
        payfastResponse.status,
        payfastResponse.statusText,
        payfastResponse.data
      );
      res.status(500).send({
        success: false,
        error: 'Payment initiation failed. PayFast returned an unexpected status.',
      });
    }
  } catch (error) {
    console.error('Payment initiation failed:', error);
    res.status(500).send({
      success: false,
      error: 'Payment initiation failed. Internal server error.',
    });
  }
});


// Function to send deposit confirmation email
function sendDepositConfirmationEmail(userId, amount) {
  const transporter = nodemailer.createTransport({
    // Configure your mail server here
    service: 'Gmail',
    auth: {
      user: 'heckyl66@gmail.com',
      pass: 'wvzqobuvijaribkb',
    },
  });

  const mailOptions = {
    from: "heckyl66@gmail.com",
    to: "spinz.spin@proton.me", 
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
      // Handle the email sending error
    } else {
      console.log("Email sent: " + info.response);
     
    }
  });
}

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


    const isMatch = await bcrypt.compare(password,Userpassword);

    if (!isMatch) {
      return res.status(400).json({ error: 'Incorrect Password' });
    }

    // Validate the withdrawal amount
    if (isNaN(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Invalid withdrawal amount' });
    }

    if (amount < 200) {
      return res.status(400).json({ error: 'Minimum withdrawal amount is R200' });
    }


    // Check if the withdrawal amount is greater than the user's balance
    if (amount > Userbalance) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const userKey = Object.keys(user)[0];
    const userRef = db.ref(`users/${userKey}`);
    
    const newBalance = Userbalance - amount;
    await userRef.update({ balance: newBalance });

    // Save withdrawal details to 'withdrawals' node
    const withdrawalRef = db.ref('withdrawals').push();
    withdrawalRef.set({
      user_id: userId,
      activity_description: 'Withdrawal',
      activity_details: `Withdrawal of R${amount} to Account No: ${Account}, Bank: ${bank}`,
      date_time: new Date().toISOString(),
    });

    const transporter = nodemailer.createTransport({
    // Configure your mail server here
    service: 'Gmail',
    auth: {
      user: 'heckyl66@gmail.com',
      pass: 'wvzqobuvijaribkb',
    },
  });

    // Send an email with the withdrawal request details
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
        // Handle TokenExpiredError and refresh token logic
      }

      const userId = decodedToken.userId;
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
