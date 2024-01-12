const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const app = express();
const saltRounds = 10; // Number of salt rounds for bcrypt
const secretKey = 'your-secret-key'; // Replace with a strong, secret key

app.use(bodyParser.json());

// Connect to MongoDB (replace 'your-database-name' with your actual database name)
mongoose.connect('mongodb+srv://pulkit:123@cluster0.xofh23l.mongodb.net/new?retryWrites=true',);
const db = mongoose.connection;

db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// User schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true  },
  password: { type: String, required: true },
});

const tokenSchema = new mongoose.Schema({
  email: { type: String, required: true },
  token: { type: String, required: true },
});

const Token = mongoose.model('Token', tokenSchema);

// Hash the password before saving to the database
userSchema.pre('save', async function (next) {
  const user = this;

  // Only hash the password if it's modified or a new user
  if (!user.isModified('password')) return next();

  try {
    const hashedPassword = await bcrypt.hash(user.password, saltRounds);
    user.password = hashedPassword;
    next();
  } catch (error) {
    return next(error);
  }
});

const User = mongoose.model('User', userSchema);

// Signup (Registration) API
app.post('/signup', async (req, res) => {
  const { email, username, password } = req.body;

  try {
    // Check if the user with the provided email already exists
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Create a new user
    const newUser = new User({
      email,
      username,
      password,
    });

    // Save the new user to the database
    await newUser.save();

    // Create and sign a JWT for the new user
    const token = jwt.sign({ userId: newUser._id, username: newUser.username }, secretKey);

    res.json({ message: 'User created successfully', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error creating user' });
  }
});








app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Verify the password using bcrypt
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

   
// Create and sign a JWT for the logged-in user
const token = jwt.sign(
  { userId: user._id, username: user.username, email: user.email },
  secretKey
);
console.log('Email:', user.email);
console.log('Token:', token);
    // Store the token in the database
    await Token.create({ email: user.email, token });
                    
    res.json({message :'Login Successfully',token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error authenticating user' });
  }
});


// Protected Route (Example)
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route!' });
});
function authenticateToken(req, res, next) {
  const authHeader = req.header('Authorization');

  if (!authHeader) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  // Check if the header starts with 'Bearer'
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Invalid token format' });
  }

  // Extract the token without the 'Bearer' prefix
  const token = authHeader.slice(7);
  console.log(token);


  jwt.verify(token, secretKey, async (err, decoded) => {
    if (err) {
      console.error(err);
      return res.status(403).json({ message: 'Forbidden' });
    }
    console.log(decoded);
  
    const user = decoded; // Use the decoded payload as the user object
    console.log(user)
    // Check if the token exists in the Token collection
    const tokenExists = await Token.findOne({ email: user.email, token });
     console.log(tokenExists)
    // if (!tokenExists) {
    //   return res.status(403).json({ message: 'Invalid token' });
    // }
  
    req.user = user;
  
    // If verification is successful and token exists, provide an access granted message
    res.status(200).json({ message: `Access granted for user: ${user.email}` });
  });
}





const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
