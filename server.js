const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const axios = require("axios");
const bcrypt = require("bcrypt");
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

function generateGroupId(length = 22) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let id = "";
  for (let i = 0; i < length; i++) {
    id += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return id;
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
  replyTo: { type: String, default: null },
  issticker: { type: Boolean, default: false }   // <-- add this
});

// Indexes for faster queries
messageSchema.index({ senderId: 1 });
messageSchema.index({ receiverId: 1 });
messageSchema.index({ replyTo: 1 });

const Message = mongoose.model("Message", messageSchema);
const groupSchema = new mongoose.Schema({
  id: { type: String, unique: true }, // 19+ digit alphanumeric
  ownerId: { type: Number, required: true },
  name: { type: String, required: true }, // optional group name
  pass: { type: String, required: true },
  creationDate: { type: Date, default: Date.now },
  members: [{ userId: Number }], // includes owner
  admins: [{ userId: Number }], // start empty
  gcpfp: { type: String, default: null } // group profile picture URL
});

const Group = mongoose.model("Group", groupSchema);

const groupRequestSchema = new mongoose.Schema({
  groupId: { type: String, required: true },
  userId: { type: Number, required: true },
  requestedAt: { type: Date, default: Date.now }
});

const GroupRequest = mongoose.model("GroupRequest", groupRequestSchema);
const groupMessageSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  groupId: { type: String, required: true },
  senderId: { type: Number, required: true },
  text: { type: String, default: "" },
  fileUrl: { type: String, default: null },
  fileType: { type: String, default: null },
  timestamp: { type: Date, default: Date.now },
  replyTo: { type: String, default: null },
  issticker: { type: Boolean, default: false }
});

groupMessageSchema.index({ groupId: 1 });
groupMessageSchema.index({ senderId: 1 });
groupMessageSchema.index({ replyTo: 1 });

const GroupMessage = mongoose.model("GroupMessage", groupMessageSchema);
const ChannelSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  ownerId: { type: Number, required: true },
  name: { type: String, required: true },
  admins: [{ userId: Number }],
  subscribers: [{ userId: Number }],
  createdAt: { type: Date, default: Date.now }
});
const Channel = mongoose.model("Channel", ChannelSchema);

const ChannelMessageSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  channelId: { type: String, required: true },
  senderId: { type: Number, required: true },
  text: String,
  fileUrl: String,
  fileType: String,
  issticker: { type: Boolean, default: false },
  reactions: [{ userId: Number, emoji: String }],
  timestamp: { type: Date, default: Date.now }
});
const ChannelMessage = mongoose.model("ChannelMessage", ChannelMessageSchema);
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

    if ((!username && !mail) || !password) {
      return res.status(400).json({ error: "username or mail and password are required" });
    }

    // Find by username OR mail
    const user = await User.findOne({
      $or: [
        username ? { username } : null,
        mail ? { mail } : null
      ].filter(Boolean) // remove nulls
    });

    if (!user) {
      return res.status(401).json({ error: "Invalid username or mail" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid password" });
    }

    user.logdate = new Date();
    await user.save();

    return res.status(200).json({
      message: "Login successful",
      authToken: user.authToken
    });
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

const typingUsers = {}; 
// typingUsers[room] = Set of userIds currently typing in that room

io.on("connection", (socket) => {
  console.log("New client connected:", socket.id);

  // Join a user-specific room using authToken for security
  socket.on("joinUserRoom", async (authToken) => {
    try {
      if (!authToken) return;

      const user = await User.findOne({ authToken });
      if (!user) {
        console.log("Invalid authToken attempted:", authToken);
        return;
      }

      socket.join(`user_${user.id}`);
      console.log(`User ${user.username} joined their room`);
    } catch (err) {
      console.error("Error joining user room:", err);
    }
  });

  // Join a group room using authToken verification
  socket.on("joinGroupRoom", async ({ groupId, authToken }) => {
    try {
      if (!authToken || !groupId) return;

      const user = await User.findOne({ authToken });
      if (!user) {
        console.log("Invalid authToken for group join:", authToken);
        return;
      }

      const group = await Group.findOne({ id: groupId });
      if (!group) {
        console.log("Group not found:", groupId);
        return;
      }

      // Only allow if user is a member of the group
      const isMember = group.members.some(m => m.userId === user.id);
      if (!isMember) {
        console.log(`User ${user.username} tried to join group ${group.name} without being a member`);
        return;
      }

      socket.join(`group_${group.id}`);
      console.log(`User ${user.username} joined group room: ${group.name}`);
    } catch (err) {
      console.error("Error joining group room:", err);
    }
  });

  // 🔥 Join a channel room (anyone with valid authToken can join)
  socket.on("joinChannelRoom", async ({ channelId, authToken }) => {
    try {
      if (!authToken || !channelId) return;

      const user = await User.findOne({ authToken });
      if (!user) {
        console.log("Invalid authToken for channel join:", authToken);
        return;
      }

      const channel = await Channel.findOne({ id: channelId });
      if (!channel) {
        console.log("Channel not found:", channelId);
        return;
      }

      socket.join(`channel_${channel.id}`);
      console.log(`User ${user.username} joined channel room: ${channel.name}`);
    } catch (err) {
      console.error("Error joining channel room:", err);
    }
  });

  // ✨ Handle typing indicator
  socket.on("typing", async ({ room, authToken }) => {
    try {
      const user = await User.findOne({ authToken });
      if (!user) return;

      if (!typingUsers[room]) typingUsers[room] = new Set();
      typingUsers[room].add(user.id);

      // Fetch all users currently typing
      const usersTyping = await User.find({ id: { $in: Array.from(typingUsers[room]) } }, "id username name");

      // Broadcast to everyone else in the room
      socket.to(room).emit("showTyping", { users: usersTyping });

      // Auto-remove after 5s if no "stopTyping"
      setTimeout(async () => {
        if (typingUsers[room] && typingUsers[room].has(user.id)) {
          typingUsers[room].delete(user.id);
          const stillTyping = await User.find({ id: { $in: Array.from(typingUsers[room]) } }, "id username name");
          socket.to(room).emit("showTyping", { users: stillTyping });
        }
      }, 5000);
    } catch (err) {
      console.error("Error in typing event:", err);
    }
  });

  // ✨ Stop typing
  socket.on("stopTyping", async ({ room, authToken }) => {
    try {
      const user = await User.findOne({ authToken });
      if (!user) return;

      if (typingUsers[room]) {
        typingUsers[room].delete(user.id);
        const stillTyping = await User.find({ id: { $in: Array.from(typingUsers[room]) } }, "id username name");
        socket.to(room).emit("showTyping", { users: stillTyping });
      }
    } catch (err) {
      console.error("Error in stopTyping event:", err);
    }
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

// Send message route
app.post("/message/:userid", async (req, res) => {
  try {
    const { userid } = req.params;
    const { authToken, text, replyTo, fileBase64, fileType, issticker } = req.body;

    if (!authToken) return res.status(400).json({ error: "authToken is required" });

    // Verify sender
    const sender = await User.findOne({ authToken });
    if (!sender) return res.status(401).json({ error: "Invalid authToken" });

    // Verify receiver
    if (!userid || isNaN(userid)) return res.status(400).json({ error: "Invalid receiver id" });
    const receiver = await User.findOne({ id: Number(userid) });
    if (!receiver) return res.status(404).json({ error: "Receiver not found" });

    // Verify replyTo if provided
    if (replyTo) {
      const originalMessage = await Message.findOne({ id: replyTo });
      if (!originalMessage) {
        return res.status(404).json({ error: "Original message to reply to not found" });
      }
    }

    // Generate unique message ID
    let messageId;
    do {
      messageId = generateMessageId();
    } while (await Message.findOne({ id: messageId }));

    // Handle file upload
    let fileUrl = null;
    let finalIsSticker = false;

    if (fileBase64 && fileType) {
      try {
        const buffer = Buffer.from(fileBase64, "base64");
        if (buffer.length > 10 * 1024 * 1024)
          return res.status(400).json({ error: "File size exceeds 10MB limit" });

        const [typeMain, typeSub] = fileType.split("/");
        if (!typeMain) return res.status(400).json({ error: "Invalid fileType" });

        const ext = typeSub || "dat";
        const fileName = `${messageId}.${ext}`;

        const form = new FormData();
        form.append("reqtype", "fileupload");
        form.append("userhash", "");
        form.append("fileToUpload", buffer, fileName);

        const catboxResponse = await axios.post("https://catbox.moe/user/api.php", form, {
          headers: form.getHeaders(),
        });

        if (!catboxResponse.data || catboxResponse.data.startsWith("ERROR")) {
          return res.status(500).json({ error: "Failed to upload file to Catbox" });
        }

        fileUrl = catboxResponse.data;
        finalIsSticker = (typeMain === "image") && Boolean(issticker);
      } catch (uploadErr) {
        console.error("File upload error:", uploadErr);
        return res.status(500).json({ error: "File upload failed" });
      }
    }

    // Save message
    const newMessage = new Message({
      id: messageId,
      senderId: sender.id,
      receiverId: receiver.id,
      text: text || "",
      fileUrl,
      fileType: fileType || null,
      replyTo: replyTo || null,
      issticker: finalIsSticker
    });
    await newMessage.save();

    // Prepare emit data
    const emitMessage = {
      ...newMessage.toObject(),
      senderUsername: sender.username,
      senderName: sender.name,
      receiverUsername: receiver.username,
      receiverName: receiver.name
    };

    // Emit to sender
    const senderRoom = `user_${sender.id}`;
    const receiverRoom = `user_${receiver.id}`;

    const senderSockets = io.sockets.adapter.rooms.get(senderRoom);
    if (senderSockets && senderSockets.size > 0) {
      io.to(senderRoom).emit("newMessage", emitMessage);
      io.to(senderRoom).emit("updateMyChats", {
        type: "private",
        id: receiver.id,
        name: receiver.name,
        username: receiver.username,
        latestMessage: `${sender.name}: ${emitMessage.text?.slice(0, 50) || ""}`,
        timestamp: emitMessage.timestamp
      });
    }

    // Emit to receiver
    const receiverSockets = io.sockets.adapter.rooms.get(receiverRoom);
    if (receiverSockets && receiverSockets.size > 0) {
      io.to(receiverRoom).emit("newMessage", emitMessage);
      io.to(receiverRoom).emit("updateMyChats", {
        type: "private",
        id: sender.id,
        name: sender.name,
        username: sender.username,
        latestMessage: `${sender.name}: ${emitMessage.text?.slice(0, 50) || ""}`,
        timestamp: emitMessage.timestamp
      });
    }

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
              issticker: r.issticker || false,
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
        issticker: msg.issticker || false,
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

app.post("/create", async (req, res) => {
  try {
    const { authToken, name, pass, gcpfpBase64, gcpfpType } = req.body;
    if (!authToken || !pass) {
      return res.status(400).json({ error: "authToken and pass are required" });
    }

    // Validate owner
    const owner = await User.findOne({ authToken });
    if (!owner) {
      return res.status(401).json({ error: "Invalid authToken" });
    }

    // Handle optional group profile picture upload
    let gcpfpUrl = null;
    if (gcpfpBase64 && gcpfpType) {
      const buffer = Buffer.from(gcpfpBase64, "base64");

      if (buffer.length > 10 * 1024 * 1024) {
        return res.status(400).json({ error: "File size exceeds 10MB limit" });
      }

      const ext = gcpfpType.split("/")[1] || "png";
      const fileName = `gcpfp_${Date.now()}.${ext}`;
      const form = new FormData();
      form.append("reqtype", "fileupload");   // ✅ required for Catbox
      form.append("userhash", "");            // optional
      form.append("fileToUpload", buffer, fileName);

      const catboxResponse = await axios.post(
        "https://catbox.moe/user/api.php",
        form,
        { headers: form.getHeaders() }
      );

      if (!catboxResponse.data) {
        return res.status(500).json({ error: "Failed to upload file to Catbox" });
      }

      if (catboxResponse.data.startsWith("ERROR")) {
        return res.status(400).json({ error: `Catbox upload failed: ${catboxResponse.data}` });
      }

      gcpfpUrl = catboxResponse.data;
    }

    // Generate unique group ID
    let groupId;
    do {
      groupId = generateGroupId();
    } while (await Group.findOne({ id: groupId }));

    // Save group
    const newGroup = new Group({
      id: groupId,
      ownerId: owner.id,
      name: name || `Group_${groupId}`,
      pass,
      members: [{ userId: owner.id }],
      admins: [],
      gcpfp: gcpfpUrl
    });

    await newGroup.save();

    return res.status(201).json({ message: "Group created", groupId });
  } catch (err) {
    console.error("Error creating group:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/addgc/:userid", async (req, res) => {
  try {
    const { authToken, groupId } = req.body;
    const { userid } = req.params;

    if (!authToken || !groupId) return res.status(400).json({ error: "authToken and groupId are required" });

    const owner = await User.findOne({ authToken });
    if (!owner) return res.status(401).json({ error: "Invalid authToken" });

    const group = await Group.findOne({ id: groupId });
    if (!group) return res.status(404).json({ error: "Group not found" });
    if (group.ownerId !== owner.id) return res.status(403).json({ error: "Only owner can invite" });

    const userToInvite = await User.findOne({ id: Number(userid) });
    if (!userToInvite) return res.status(404).json({ error: "User not found" });

    const alreadyRequested = await GroupRequest.findOne({ groupId, userId: userToInvite.id });
    if (alreadyRequested) return res.status(400).json({ error: "User already invited" });

    const newRequest = new GroupRequest({ groupId, userId: userToInvite.id });
    await newRequest.save();

    return res.status(200).json({ message: `Invite sent to ${userToInvite.username}` });
  } catch (err) {
    console.error("Error inviting user:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/requests", async (req, res) => {
  try {
    const { authToken } = req.query;
    if (!authToken) return res.status(400).json({ error: "authToken is required" });

    const user = await User.findOne({ authToken });
    if (!user) return res.status(401).json({ error: "Invalid authToken" });

    const requests = await GroupRequest.find({ userId: user.id });
    const detailed = await Promise.all(requests.map(async (r) => {
      const group = await Group.findOne({ id: r.groupId });
      return {
        groupId: group.id,
        groupName: group.name,
        ownerId: group.ownerId,
        requestedAt: r.requestedAt
      };
    }));

    return res.status(200).json(detailed);
  } catch (err) {
    console.error("Error fetching requests:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/join/:groupid", async (req, res) => {
  try {
    const { authToken } = req.body;
    const { groupid } = req.params;

    if (!authToken) 
      return res.status(400).json({ error: "authToken is required" });

    const user = await User.findOne({ authToken });
    if (!user) 
      return res.status(401).json({ error: "Invalid authToken" });

    const group = await Group.findOne({ id: groupid });
    if (!group) 
      return res.status(404).json({ error: "Group not found" });

    // Check if user is already a member
    const isMember = group.members.find(m => m.userId === user.id);
    if (isMember) 
      return res.status(400).json({ error: "Already a member of this group" });

    // Add user to members
    group.members.push({ userId: user.id });
    await group.save();

    // Remove any pending request (optional)
    await GroupRequest.deleteOne({ groupId: groupid, userId: user.id });

    return res.status(200).json({ message: `Joined group ${group.name}` });
  } catch (err) {
    console.error("Error joining group:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/kick/:userid", async (req, res) => {
  try {
    const { authToken, groupId } = req.body;
    const { userid } = req.params;

    if (!authToken || !groupId) 
      return res.status(400).json({ error: "authToken and groupId are required" });

    const requester = await User.findOne({ authToken });
    if (!requester) 
      return res.status(401).json({ error: "Invalid authToken" });

    const group = await Group.findOne({ id: groupId });
    if (!group) 
      return res.status(404).json({ error: "Group not found" });

    // Only owner or admin can kick
    const isOwner = group.ownerId === requester.id;
    const isAdmin = group.admins.some(a => a.userId === requester.id);
    if (!isOwner && !isAdmin) 
      return res.status(403).json({ error: "Only owner or admins can kick members" });

    // Check if target is member
    const memberIndex = group.members.findIndex(m => m.userId === Number(userid));
    if (memberIndex === -1) 
      return res.status(404).json({ error: "User is not a member" });

    // Prevent kicking the owner
    if (Number(userid) === group.ownerId) 
      return res.status(400).json({ error: "Owner cannot be kicked" });

    group.members.splice(memberIndex, 1);
    await group.save();

    return res.status(200).json({ message: "User kicked from group" });
  } catch (err) {
    console.error("Error kicking user:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/leave/:groupid", async (req, res) => {
  try {
    const { authToken } = req.body;
    const { groupid } = req.params;

    if (!authToken) 
      return res.status(400).json({ error: "authToken is required" });

    const user = await User.findOne({ authToken });
    if (!user) 
      return res.status(401).json({ error: "Invalid authToken" });

    const group = await Group.findOne({ id: groupid });
    if (!group) 
      return res.status(404).json({ error: "Group not found" });

    // Owner cannot leave
    if (group.ownerId === user.id) 
      return res.status(400).json({ error: "Owner cannot leave the group. Transfer ownership or delete group." });

    // Remove member
    const memberIndex = group.members.findIndex(m => m.userId === user.id);
    if (memberIndex === -1) 
      return res.status(400).json({ error: "You are not a member of this group" });

    group.members.splice(memberIndex, 1);
    await group.save();

    return res.status(200).json({ message: `Left group ${group.name}` });
  } catch (err) {
    console.error("Error leaving group:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/groupmessage/:groupid", async (req, res) => {
  try {
    const { groupid } = req.params;
    const { authToken, text, replyTo, fileBase64, fileType, issticker } = req.body;

    if (!authToken) {
      return res.status(400).json({ error: "authToken is required" });
    }

    // Verify sender
    const sender = await User.findOne({ authToken });
    if (!sender) {
      return res.status(401).json({ error: "Invalid authToken" });
    }

    // Verify group
    const group = await Group.findOne({ id: groupid });
    if (!group) {
      return res.status(404).json({ error: "Group not found" });
    }

    // Generate unique message ID
    let messageId;
    do {
      messageId = generateMessageId();
    } while (await GroupMessage.findOne({ id: messageId }));

    // Handle optional file upload
    let fileUrl = null;
    let finalIsSticker = false;
    if (fileBase64 && fileType) {
      const buffer = Buffer.from(fileBase64, "base64");

      // Check size
      if (buffer.length > 10 * 1024 * 1024) {
        return res.status(400).json({ error: "File size exceeds 10MB limit" });
      }

      const [typeMain, typeSub] = fileType.split("/");
      const ext = typeSub || "dat";
      const fileName = `${messageId}.${ext}`;

      const form = new FormData();
      form.append("reqtype", "fileupload");   // ✅ required by Catbox
      form.append("userhash", "");            // optional
      form.append("fileToUpload", buffer, fileName);

      let catboxResponse;
      try {
        catboxResponse = await axios.post("https://catbox.moe/user/api.php", form, {
          headers: form.getHeaders(),
        });
      } catch (uploadErr) {
        console.error("Catbox upload error:", uploadErr.message);
        return res.status(502).json({ error: "Failed to reach Catbox upload service" });
      }

      if (!catboxResponse.data) {
        return res.status(500).json({ error: "Empty response from Catbox" });
      }

      if (typeof catboxResponse.data === "string" && catboxResponse.data.startsWith("ERROR")) {
        return res.status(400).json({ error: `Catbox upload failed: ${catboxResponse.data}` });
      }

      fileUrl = catboxResponse.data;

      // Mark as sticker only if frontend set it AND it's an image
      finalIsSticker = (typeMain === "image") && Boolean(issticker);
    }

    // Save group message
    const newMessage = new GroupMessage({
      id: messageId,
      groupId: group.id,
      senderId: sender.id,
      text: text || "",
      fileUrl,
      fileType: fileType || null,
      replyTo: replyTo || null,
      issticker: finalIsSticker,
    });
    await newMessage.save();

    const emitMessage = {
      ...newMessage.toObject(),
      senderUsername: sender.username,
      senderName: sender.name,
    };

    // Emit to group members
    io.to(`group_${group.id}`).emit("newGroupMessage", emitMessage);

    // Update chats list
    const chatUpdate = {
      type: "group",
      id: group.id,
      name: group.name,
      latestMessage: `${sender.name}: ${emitMessage.text?.slice(0, 50) || ""}`,
      timestamp: emitMessage.timestamp,
    };
    io.to(`group_${group.id}`).emit("updateMyChats", chatUpdate);

    return res.status(201).json({
      message: "Message sent to group successfully",
      data: emitMessage,
    });
  } catch (err) {
    console.error("Error sending group message:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Get group messages with replies
app.get("/groupmessages/:groupid", async (req, res) => {
  try {
    const { groupid } = req.params;
    const { limit = 50, from, to } = req.query;

    const query = { groupId: groupid, replyTo: null };
    if (from || to) query.timestamp = {};
    if (from) query.timestamp.$gte = new Date(from);
    if (to) query.timestamp.$lte = new Date(to);

    const messages = await GroupMessage.find(query)
      .sort({ timestamp: -1 })
      .limit(Number(limit));

    const messageIds = messages.map(msg => msg.id);
    const replies = await GroupMessage.find({ replyTo: { $in: messageIds } }).sort({ timestamp: 1 });

    const messagesWithReplies = await Promise.all(messages.map(async (msg) => {
      const sender = await User.findOne({ id: msg.senderId });

      const msgReplies = await Promise.all(
        replies.filter(r => r.replyTo === msg.id).map(async (r) => {
          const replySender = await User.findOne({ id: r.senderId });
          return {
            id: r.id,
            senderId: r.senderId,
            senderUsername: replySender?.username || null,
            senderName: replySender?.name || null,
            text: r.text,
            fileUrl: r.fileUrl,
            fileType: r.fileType,
            issticker: r.issticker || false,  // <-- added sticker flag
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
        text: msg.text,
        fileUrl: msg.fileUrl,
        fileType: msg.fileType,
        issticker: msg.issticker || false,  // <-- added sticker flag
        timestamp: msg.timestamp,
        replyTo: msg.replyTo,
        replies: msgReplies
      };
    }));

    return res.status(200).json(messagesWithReplies);
  } catch (err) {
    console.error("Error fetching group messages:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/mychats", async (req, res) => {
  try {
    const { authToken } = req.query;
    if (!authToken) return res.status(400).json({ error: "authToken is required" });

    const me = await User.findOne({ authToken });
    if (!me) return res.status(401).json({ error: "Invalid authToken" });

    // ----- PRIVATE CHATS -----
    const messages = await Message.find({
      $or: [{ senderId: me.id }, { receiverId: me.id }]
    }).sort({ timestamp: -1 });

    const privateChatsMap = new Map(); // key: otherUserId, value: latest message
    messages.forEach(msg => {
      const otherId = msg.senderId === me.id ? msg.receiverId : msg.senderId;
      if (!privateChatsMap.has(otherId)) privateChatsMap.set(otherId, msg);
    });

    const privateChats = await Promise.all(
      Array.from(privateChatsMap.entries()).map(async ([otherId, msg]) => {
        const otherUser = await User.findOne({ id: otherId });
        const sender = await User.findOne({ id: msg.senderId });
        return {
          type: "private",
          id: otherUser.id,
          name: otherUser.name,
          username: otherUser.username,
          latestMessage: `${sender.name}: ${msg.text?.slice(0, 50) || ""}`,
          timestamp: msg.timestamp
        };
      })
    );

    // ----- GROUP CHATS -----
    const groups = await Group.find({ "members.userId": me.id });
    const groupChats = await Promise.all(
      groups.map(async group => {
        const latestMsg = await GroupMessage.findOne({ groupId: group.id })
          .sort({ timestamp: -1 });

        let latestText = "";
        if (latestMsg) {
          const sender = await User.findOne({ id: latestMsg.senderId });
          latestText = `${sender.name}: ${latestMsg.text?.slice(0, 50) || ""}`;
        }

        return {
          type: "group",
          id: group.id,
          name: group.name,
          latestMessage: latestText,
          timestamp: latestMsg?.timestamp || group.creationDate
        };
      })
    );

    // Merge and sort by timestamp descending
    const allChats = [...privateChats, ...groupChats].sort((a, b) => b.timestamp - a.timestamp);

    return res.status(200).json(allChats);

  } catch (err) {
    console.error("Error fetching mychats:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/createchannel", async (req, res) => {
  try {
    const { authToken, name } = req.body;
    if (!authToken || !name) return res.status(400).json({ error: "Missing fields" });

    const user = await User.findOne({ authToken });
    if (!user) return res.status(401).json({ error: "Invalid authToken" });

    const existing = await Channel.find({ ownerId: user.id });
    if (existing.length >= 2) return res.status(403).json({ error: "Max 2 channels per user" });

    const channelId = generateMessageId();
    const newChannel = new Channel({
      id: channelId,
      ownerId: user.id,
      name,
      admins: [{ userId: user.id }]
    });
    await newChannel.save();

    return res.status(201).json({ message: "Channel created", channel: newChannel });
  } catch (err) {
    console.error("Error creating channel:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/channelmessage/:channelId", async (req, res) => {
  try {
    const { channelId } = req.params;
    const { authToken, text, fileBase64, fileType, issticker } = req.body;

    // Validate auth
    if (!authToken) {
      return res.status(400).json({ error: "authToken is required" });
    }

    const sender = await User.findOne({ authToken });
    if (!sender) {
      return res.status(401).json({ error: "Invalid authToken" });
    }

    // Validate channel
    const channel = await Channel.findOne({ id: channelId });
    if (!channel) {
      return res.status(404).json({ error: "Channel not found" });
    }

    // Admin/owner restriction
    const isAdmin = channel.admins.some(a => a.userId === sender.id) || channel.ownerId === sender.id;
    if (!isAdmin) {
      return res.status(403).json({ error: "Only admins/owner can send messages" });
    }

    // Handle optional file upload
    let fileUrl = null;
    let finalIsSticker = false;
    if (fileBase64 && fileType) {
      const buffer = Buffer.from(fileBase64, "base64");

      if (buffer.length > 10 * 1024 * 1024) {
        return res.status(400).json({ error: "File size exceeds 10MB limit" });
      }

      const [typeMain, typeSub] = fileType.split("/");
      const ext = typeSub || "dat";
      const fileName = `${generateMessageId()}.${ext}`;

      const form = new FormData();
      form.append("reqtype", "fileupload");   // ✅ required
      form.append("userhash", "");            // optional
      form.append("fileToUpload", buffer, fileName);

      let catboxResponse;
      try {
        catboxResponse = await axios.post("https://catbox.moe/user/api.php", form, {
          headers: form.getHeaders(),
        });
      } catch (uploadErr) {
        console.error("Catbox upload error:", uploadErr.message);
        return res.status(502).json({ error: "Failed to reach Catbox upload service" });
      }

      if (!catboxResponse.data) {
        return res.status(500).json({ error: "Empty response from Catbox" });
      }

      if (typeof catboxResponse.data === "string" && catboxResponse.data.startsWith("ERROR")) {
        return res.status(400).json({ error: `Catbox upload failed: ${catboxResponse.data}` });
      }

      fileUrl = catboxResponse.data;
      finalIsSticker = (typeMain === "image") && Boolean(issticker);
    }

    // Generate unique message ID
    let messageId;
    do {
      messageId = generateMessageId();
    } while (await ChannelMessage.findOne({ id: messageId }));

    // Save message
    const newMsg = new ChannelMessage({
      id: messageId,
      channelId,
      senderId: sender.id,
      text: text || "",
      fileUrl,
      fileType: fileType || null,
      issticker: finalIsSticker,
    });
    await newMsg.save();

    // Prepare emit object
    const emitMsg = {
  ...newMsg.toObject(),
  senderName: sender.name,
  senderUsername: sender.username
};

    // Emit to all subscribers of the channel
    io.to(`channel_${channelId}`).emit("newChannelMessage", emitMsg);

io.to(`channel_${channelId}`).emit("updateMyChats", {
  type: "channel",
  id: channel.id,
  name: channel.name,
  latestMessage: `${sender.name}: ${emitMsg.text?.slice(0, 50) || ""}`,
  timestamp: emitMsg.timestamp
});

    return res.status(201).json({ message: "Message sent", data: emitMsg });
  } catch (err) {
    console.error("Error sending channel message:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/promotechanneluser/:channelId", async (req, res) => {
  const { channelId } = req.params;
  const { authToken, userId } = req.body;

  const requester = await User.findOne({ authToken });
  if (!requester) return res.status(401).json({ error: "Invalid authToken" });

  const channel = await Channel.findOne({ id: channelId });
  if (!channel) return res.status(404).json({ error: "Channel not found" });

  if (channel.ownerId !== requester.id) return res.status(403).json({ error: "Only owner can promote" });

  if (!channel.admins.some(a => a.userId === userId)) {
    channel.admins.push({ userId });
    await channel.save();
  }

  return res.status(200).json({ message: "User promoted to admin" });
});

app.post("/subscribe/:channelId", async (req, res) => {
  const { channelId } = req.params;
  const { authToken } = req.body;

  const user = await User.findOne({ authToken });
  if (!user) return res.status(401).json({ error: "Invalid authToken" });

  const channel = await Channel.findOne({ id: channelId });
  if (!channel) return res.status(404).json({ error: "Channel not found" });

  if (!channel.subscribers.some(s => s.userId === user.id)) {
    channel.subscribers.push({ userId: user.id });
    await channel.save();
  }

  return res.status(200).json({ message: "Subscribed successfully" });
});
app.post("/react/:messageId", async (req, res) => {
  const { messageId } = req.params;
  const { authToken, emoji } = req.body;

  const user = await User.findOne({ authToken });
  if (!user) return res.status(401).json({ error: "Invalid authToken" });

  const message = await ChannelMessage.findOne({ id: messageId });
  if (!message) return res.status(404).json({ error: "Message not found" });

  message.reactions.push({ userId: user.id, emoji });
  await message.save();

  io.to(`channel_${message.channelId}`).emit("reactionAdded", {
    messageId,
    userId: user.id,
    emoji
  });

  return res.status(200).json({ message: "Reaction added" });
});
// Start server
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
