
require("dotenv").config();

const dns = require("node:dns");
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");

// Some Windows/network configurations expose a non-working localhost DNS
// resolver to Node. Atlas SRV connection strings need DNS to discover shards.
const mongoDnsServers = (process.env.MONGODB_DNS_SERVERS || "1.1.1.1,8.8.8.8")
    .split(",")
    .map(server => server.trim())
    .filter(Boolean);

if (mongoDnsServers.length > 0) {
    dns.setServers(mongoDnsServers);
}

// `dns.setServers()` affects SRV/TXT queries but not Node's default
// `dns.lookup()`. Give the MongoDB driver a lookup function that uses the
// same working DNS servers for the Atlas shard hostnames as well.
function mongoLookup(hostname, options, callback) {
    const requestedFamily = typeof options === "object" ? options.family : 0;
    const resolve = requestedFamily === 6 ? dns.resolve6 : dns.resolve4;

    resolve(hostname, (error, addresses) => {
        if (error) return callback(error);

        const family = requestedFamily === 6 ? 6 : 4;
        if (typeof options === "object" && options.all) {
            return callback(null, addresses.map(address => ({ address, family })));
        }

        callback(null, addresses[0], family);
    });
}

const app = express();

app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, { lookup: mongoLookup })
.then(() => console.log("MongoDB Connected Successfully"))
.catch(err => console.log("MongoDB Error:", err.message));

// User Schema
const UserSchema = new mongoose.Schema({
    fullName: String,
    username: { type: String, unique: true },
    email: { type: String, unique: true },
    phone: String,
    passwordHash: String,
    createdAt: { type: Date, default: Date.now },
    loginHistory: [Date]
});

const User = mongoose.model("User", UserSchema);

// Signup API
app.post("/signup", async (req, res) => {
    try {
        const { fullName, username, email, phone, password } = req.body;

        if (!fullName || !username || !email || !password) {
            return res.status(400).json({ message: "Required fields missing" });
        }

        const existing = await User.findOne({
            $or: [{ email }, { username }]
        });

        if (existing) {
            return res.status(409).json({ message: "User already exists" });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const user = await User.create({
            fullName,
            username,
            email,
            phone,
            passwordHash
        });

        res.status(201).json({
            message: "Signup successful",
            userId: user._id
        });

    } catch (error) {
        res.status(500).json({ message: "Signup failed" });
    }
});

// Login API
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        const valid = await bcrypt.compare(password, user.passwordHash);

        if (!valid) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        user.loginHistory.push(new Date());
        await user.save();

        res.json({ message: "Login successful" });

    } catch (error) {
        res.status(500).json({ message: "Login failed" });
    }
});

// Start server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
