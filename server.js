const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const axios = require("axios");
const bcrypt = require("bcryptjs");
const FormData = require("form-data");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
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
function generateMessageId() {
  const timestamp = Date.now();
  const random = Math.floor(100000000 + Math.random() * 900000000);
  return `${timestamp}${random}`;
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
const messageSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  senderId: { type: Number, required: true },
  receiverId: { type: Number, required: true },
  text: { type: String, default: "" },
  fileUrl: { type: String, default: null },
  fileType: { type: String, default: null },
  timestamp: { type: Date, default: Date.now },
  replyTo: { type: String, default: null }
});

// Indexes for faster queries
messageSchema.index({ senderId: 1 });
messageSchema.index({ receiverId: 1 });
messageSchema.index({ replyTo: 1 });

const Message = mongoose.model("Message", messageSchema);
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

io.on("connection", (socket) => {
  console.log("New client connected:", socket.id);

  socket.on("joinRoom", (userId) => {
    socket.join(`user_${userId}`);
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

// Send message route
// Send message route
app.post("/message/:userid", async (req, res) => {
  try {
    const { userid } = req.params;
    const { authToken, text, replyTo, fileBase64, fileType } = req.body;

    if (!authToken) return res.status(400).json({ error: "authToken is required" });

    const sender = await User.findOne({ authToken });
    if (!sender) return res.status(401).json({ error: "Invalid authToken" });

    const receiver = await User.findOne({ id: Number(userid) });
    if (!receiver) return res.status(404).json({ error: "Receiver not found" });

    if (replyTo) {
      const originalMessage = await Message.findOne({ id: replyTo });
      if (!originalMessage) return res.status(404).json({ error: "Original message to reply to not found" });
    }

    let messageId;
    do {
      messageId = generateMessageId();
    } while (await Message.findOne({ id: messageId }));

    let fileUrl = null;
    if (fileBase64 && fileType) {
      const buffer = Buffer.from(fileBase64, "base64");
      if (buffer.length > 10 * 1024 * 1024)
        return res.status(400).json({ error: "File size exceeds 10MB limit" });

      let ext = fileType.split("/")[1] || "dat";
      const fileName = `${messageId}.${ext}`;
      const form = new FormData();
      form.append("fileToUpload", buffer, fileName);

      const catboxResponse = await axios.post("https://catbox.moe/user/api.php", form, {
        headers: form.getHeaders(),
        params: { reqtype: "fileupload", userhash: "" }
      });

      if (!catboxResponse.data) return res.status(500).json({ error: "Failed to upload file to Catbox" });
      fileUrl = catboxResponse.data;
    }

    const newMessage = new Message({
      id: messageId,
      senderId: sender.id,
      receiverId: receiver.id,
      text: text || "",
      fileUrl,
      fileType: fileType || null,
      replyTo: replyTo || null
    });

    await newMessage.save();

    const emitMessage = {
      ...newMessage.toObject(),
      senderUsername: sender.username,
      senderName: sender.name,
      receiverUsername: receiver.username,
      receiverName: receiver.name
    };

    io.to(`user_${sender.id}`).emit("newMessage", emitMessage);
    io.to(`user_${receiver.id}`).emit("newMessage", emitMessage);

    return res.status(201).json({ message: "Message sent successfully", data: emitMessage });
  } catch (err) {
    console.error("Error sending message:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Get messages route with replies
app.get("/messages", async (req, res) => {
  try {
    const { userid, limit = 50, from, to } = req.query;
    if (!userid) return res.status(400).json({ error: "userid is required" });

    const query = { $or: [{ senderId: Number(userid) }, { receiverId: Number(userid) }] };
    if (from || to) query.timestamp = {};
    if (from) query.timestamp.$gte = new Date(from);
    if (to) query.timestamp.$lte = new Date(to);

    const messages = await Message.find({ ...query, replyTo: null })
      .sort({ timestamp: -1 })
      .limit(Number(limit));

    const messageIds = messages.map(msg => msg.id);
    const replies = await Message.find({ replyTo: { $in: messageIds } }).sort({ timestamp: 1 });

    const messagesWithReplies = await Promise.all(messages.map(async (msg) => {
      const sender = await User.findOne({ id: msg.senderId });
      const receiver = await User.findOne({ id: msg.receiverId });

      const msgReplies = await Promise.all(
        replies
          .filter(r => r.replyTo === msg.id)
          .map(async (r) => {
            const replySender = await User.findOne({ id: r.senderId });
            const replyReceiver = await User.findOne({ id: r.receiverId });
            return {
              id: r.id,
              senderId: r.senderId,
              senderUsername: replySender?.username || null,
              senderName: replySender?.name || null,
              receiverId: r.receiverId,
              receiverUsername: replyReceiver?.username || null,
              receiverName: replyReceiver?.name || null,
              text: r.text,
              fileUrl: r.fileUrl,
              fileType: r.fileType,
              timestamp: r.timestamp,
              replyTo: r.replyTo
            };
          })
      );

      return {
        id: msg.id,
        senderId: msg.senderId,
        senderUsername: sender?.username || null,
        senderName: sender?.name || null,
        receiverId: msg.receiverId,
        receiverUsername: receiver?.username || null,
        receiverName: receiver?.name || null,
        text: msg.text,
        fileUrl: msg.fileUrl,
        fileType: msg.fileType,
        timestamp: msg.timestamp,
        replyTo: msg.replyTo,
        replies: msgReplies
      };
    }));

    return res.status(200).json(messagesWithReplies);
  } catch (err) {
    console.error("Error fetching messages:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});
// Start server
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
