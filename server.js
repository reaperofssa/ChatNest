const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect("mongodb://127.0.0.1:27017/usersdb", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ Connected to MongoDB"))
.catch(err => console.error("❌ MongoDB connection error:", err));

// Default images
const DEFAULT_PROFILE_IMG = "https://example.com/default-profile.png";
const DEFAULT_BANNER_IMG = "https://example.com/default-banner.png";

// Helper functions
function generateUserId() {
  return Math.floor(100000000 + Math.random() * 900000000); // 9-digit number
}

function generateAuthToken(length = 197) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let token = "";
  for (let i = 0; i < length; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
}

// User Schema
const userSchema = new mongoose.Schema({
  id: { type: Number, unique: true },
  username: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  mail: { type: String, required: true },
  password: { type: String, required: true },
  bio: { type: String, default: "" },
  authToken: { type: String, required: true, unique: true },
  premium: { type: Boolean, default: false },
  verified: { type: Boolean, default: false },
  pnk: { type: Number, default: 5 },
  regdate: { type: Date, default: Date.now },
  logdate: { type: Date, default: Date.now },
  profileimg: { type: String, default: DEFAULT_PROFILE_IMG },
  bannerimg: { type: String, default: DEFAULT_BANNER_IMG },
  friends: { type: [Number], default: [] } // store friends by user id
});

// User Model
const User = mongoose.model("User", userSchema);

// Register route
app.post("/register", async (req, res) => {
  try {
    const { username, name, mail, password, bio } = req.body;

    if (!username || !name || !mail || !password) {
      return res.status(400).json({ error: "username, name, mail and password are required" });
    }

    const exists = await User.findOne({ username });
    if (exists) {
      return res.status(409).json({ error: "Username already taken" });
    }

    let userId, authToken, idExists, tokenExists;

    do {
      userId = generateUserId();
      idExists = await User.findOne({ id: userId });
    } while (idExists);

    do {
      authToken = generateAuthToken();
      tokenExists = await User.findOne({ authToken });
    } while (tokenExists);

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      id: userId,
      username,
      name,
      mail,
      password: hashedPassword,
      bio,
      authToken
    });

    await newUser.save();

    return res.status(201).json({
      message: "User registered successfully",
      user: { username, name, mail, bio }
    });
  } catch (err) {
    console.error("Error registering user:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Login route
app.post("/login", async (req, res) => {
  try {
    const { username, mail, password } = req.body;

    if (!username || !mail || !password) {
      return res.status(400).json({ error: "username, mail and password are required" });
    }

    const user = await User.findOne({ username, mail });
    if (!user) {
      return res.status(401).json({ error: "Invalid username or mail" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid password" });
    }

    user.logdate = new Date();
    await user.save();

    return res.status(200).json({ message: "Login successful", authToken: user.authToken });
  } catch (err) {
    console.error("Error logging in:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Public user route
app.get("/user/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json({
      id: user.id,
      username: user.username,
      name: user.name,
      bio: user.bio,
      verified: user.verified,
      premium: user.premium,
      pnk: user.pnk,
      regdate: user.regdate,
      logdate: user.logdate,
      profileimg: user.profileimg,
      bannerimg: user.bannerimg
    });
  } catch (err) {
    console.error("Error fetching user:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Me route
app.post("/me", async (req, res) => {
  try {
    const { authToken } = req.body;

    if (!authToken) {
      return res.status(400).json({ error: "authToken is required" });
    }

    const user = await User.findOne({ authToken });
    if (!user) {
      return res.status(401).json({ error: "Invalid authToken" });
    }

    return res.status(200).json({
      id: user.id,
      username: user.username,
      name: user.name,
      mail: user.mail,
      bio: user.bio,
      verified: user.verified,
      premium: user.premium,
      pnk: user.pnk,
      regdate: user.regdate,
      logdate: user.logdate,
      profileimg: user.profileimg,
      bannerimg: user.bannerimg,
      friends: user.friends
    });
  } catch (err) {
    console.error("Error fetching /me:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Add friend route
app.post("/add/:username", async (req, res) => {
  try {
    const { authToken } = req.body;
    const { username } = req.params;

    const me = await User.findOne({ authToken });
    if (!me) return res.status(401).json({ error: "Invalid authToken" });

    const friend = await User.findOne({ username });
    if (!friend) return res.status(404).json({ error: "User not found" });

    if (me.id === friend.id) {
      return res.status(400).json({ error: "You cannot add yourself" });
    }

    if (!me.friends.includes(friend.id)) me.friends.push(friend.id);
    if (!friend.friends.includes(me.id)) friend.friends.push(me.id);

    await me.save();
    await friend.save();

    return res.status(200).json({ message: `You are now friends with ${friend.username}` });
  } catch (err) {
    console.error("Error adding friend:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Delete friend route
app.post("/delfriend/:username", async (req, res) => {
  try {
    const { authToken } = req.body;
    const { username } = req.params;

    const me = await User.findOne({ authToken });
    if (!me) return res.status(401).json({ error: "Invalid authToken" });

    const friend = await User.findOne({ username });
    if (!friend) return res.status(404).json({ error: "User not found" });

    me.friends = me.friends.filter(id => id !== friend.id);
    friend.friends = friend.friends.filter(id => id !== me.id);

    await me.save();
    await friend.save();

    return res.status(200).json({ message: `You are no longer friends with ${friend.username}` });
  } catch (err) {
    console.error("Error deleting friend:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});
// Friends list route
app.get("/friends/:username", async (req, res) => {
  try {
    const { username } = req.params;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Fetch friend details
    const friends = await User.find({ id: { $in: user.friends } }, "id username name");

    return res.status(200).json({
      username: user.username,
      friends: friends.map(friend => ({
        id: friend.id,
        username: friend.username,
        name: friend.name
      }))
    });
  } catch (err) {
    console.error("Error fetching friends:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});
// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
