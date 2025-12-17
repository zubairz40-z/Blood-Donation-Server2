const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();



const app = express();
app.use(express.json());

// ---------------- CORS ----------------
const allowedOrigins = [
  
  process.env.CLIENT_URL,
  "https://blood-drop-b7711.web.app",
].filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error("Not allowed by CORS: " + origin));
    },
    credentials: true,
  })
);

app.options(/.*/, cors());

// ---------------- Firebase Admin ----------------
// Put FIREBASE_SERVICE_ACCOUNT as JSON string in env for production.
// Local: you can skip it (then /jwt token flow will not work, email fallback still works)
if (!admin.apps.length && process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log("✅ Firebase admin initialized");
  } catch (e) {
    console.error("❌ FIREBASE_SERVICE_ACCOUNT JSON parse failed:", e.message);
  }
}

// ---------------- Mongo ----------------
const client = new MongoClient(process.env.DB_URI, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

// ---------------- Helpers ----------------
const normalizeEmail = (email) =>
  typeof email === "string" ? email.trim().toLowerCase() : "";

const createToken = (payload) =>
  jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });

const verifyJWT = (req, res, next) => {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized (no token)" });
  }

  const token = auth.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "Unauthorized (invalid token)" });
    req.decoded = decoded; // { email, uid? }
    next();
  });
};

async function run() {
  await client.connect();
  console.log("✅ Mongo connected");

  const db = client.db("bloodDB");

  const usersCollection = db.collection("users");
  const fundingsCollection = db.collection("fundings");

  // ✅ support multiple collection names
  const donationRequestsA = db.collection("donationRequests");
  const donationRequestsB = db.collection("donation_requests");
  const donationRequestsC = db.collection("donation_Requests");

  async function getRequestsCollection() {
    const [a, b, c] = await Promise.all([
      donationRequestsA.estimatedDocumentCount(),
      donationRequestsB.estimatedDocumentCount(),
      donationRequestsC.estimatedDocumentCount(),
    ]);

    if (a > 0) return donationRequestsA;
    if (b > 0) return donationRequestsB;
    if (c > 0) return donationRequestsC;
    return donationRequestsA;
  }

  const getDBUser = async (email) => {
    const e = normalizeEmail(email);
    if (!e) return null;
    return usersCollection.findOne({ email: e });
  };

  // ---------------- Role middlewares ----------------
  const verifyAdmin = async (req, res, next) => {
    const me = await getDBUser(req.decoded?.email);
    if (!me || me.role !== "admin") return res.status(403).send({ message: "Forbidden: Admin only" });
    next();
  };

  const verifyVolunteerOrAdmin = async (req, res, next) => {
    const me = await getDBUser(req.decoded?.email);
    if (!me || !["admin", "volunteer"].includes(me.role)) {
      return res.status(403).send({ message: "Forbidden: Admin/Volunteer only" });
    }
    next();
  };

  const verifyNotBlocked = async (req, res, next) => {
    const me = await getDBUser(req.decoded?.email);
    if (me?.status === "blocked") {
      return res.status(403).send({ message: "Blocked users cannot perform this action" });
    }
    next();
  };

  // ---------------- Base routes ----------------
  app.get("/", (req, res) => res.send("✅ API running"));

  app.get("/health", async (req, res) => {
    try {
      const ping = await db.command({ ping: 1 });
      res.send({ ok: true, ping });
    } catch (e) {
      res.status(500).send({ ok: false, error: e.message });
    }
  });

  // ---------------- JWT exchange ----------------
  // Accepts:
  // 1) { token: firebaseIdToken } (production)
  // 2) { email } (local fallback)
  app.post("/jwt", async (req, res) => {
    try {
      const { token, email } = req.body || {};

      // 1) Firebase token flow
      if (token) {
        if (!admin.apps.length) {
          return res.status(500).send({
            message: "Firebase admin not configured (FIREBASE_SERVICE_ACCOUNT missing)",
          });
        }

        const decoded = await admin.auth().verifyIdToken(token);
        const userEmail = normalizeEmail(decoded.email);
        if (!userEmail) return res.status(401).send({ message: "Unauthorized (no email)" });

        // ✅ upsert so jwt works even before /users is called
        await usersCollection.updateOne(
          { email: userEmail },
          {
            $setOnInsert: {
              email: userEmail,
              role: "donor",
              status: "active",
              createdAt: new Date(),
            },
            $set: { updatedAt: new Date() },
          },
          { upsert: true }
        );

        const serverToken = createToken({ email: userEmail, uid: decoded.uid });
        return res.send({ token: serverToken });
      }

      // 2) Email fallback flow
      const safeEmail = normalizeEmail(email);
      if (!safeEmail) return res.status(400).send({ message: "Token or email required" });

      // ✅ upsert for fallback too
      await usersCollection.updateOne(
        { email: safeEmail },
        {
          $setOnInsert: {
            email: safeEmail,
            role: "donor",
            status: "active",
            createdAt: new Date(),
          },
          $set: { updatedAt: new Date() },
        },
        { upsert: true }
      );

      const serverToken = createToken({ email: safeEmail });
      res.send({ token: serverToken });
    } catch (e) {
      console.log("JWT error:", e.message);
      res.status(401).send({ message: "Unauthorized" });
    }
  });

  // ---------------- USERS ----------------
  app.post("/users", async (req, res) => {
    try {
      const u = req.body || {};
      const email = normalizeEmail(u?.email);
      if (!email) return res.status(400).send({ message: "Email is required" });

      const existing = await usersCollection.findOne({ email });

      const safeUser = {
        name: u?.name || existing?.name || "",
        email,
        avatar: u?.avatar || existing?.avatar || "",
        bloodGroup: u?.bloodGroup || existing?.bloodGroup || "",
        district: u?.district || existing?.district || "",
        upazila: u?.upazila || existing?.upazila || "",
        role: existing?.role || "donor",
        status: existing?.status || "active",
      };

      const result = await usersCollection.updateOne(
        { email },
        { $set: { ...safeUser, updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } },
        { upsert: true }
      );

      res.send(result);
    } catch (e) {
      res.status(500).send({ message: "Failed to save user", error: e.message });
    }
  });

  app.get("/users/me", verifyJWT, async (req, res) => {
    const email = normalizeEmail(req.decoded?.email);
    const me = await usersCollection.findOne({ email });
    if (!me) return res.status(404).send({ message: "User not found in database." });
    res.send(me);
  });

  app.patch("/users/me", verifyJWT, verifyNotBlocked, async (req, res) => {
    const email = normalizeEmail(req.decoded?.email);

    const { name, avatar, district, upazila, bloodGroup } = req.body || {};
    const updateDoc = {
      ...(name !== undefined ? { name } : {}),
      ...(avatar !== undefined ? { avatar } : {}),
      ...(district !== undefined ? { district } : {}),
      ...(upazila !== undefined ? { upazila } : {}),
      ...(bloodGroup !== undefined ? { bloodGroup } : {}),
      updatedAt: new Date(),
    };

    const result = await usersCollection.updateOne({ email }, { $set: updateDoc });
    res.send(result);
  });

  app.get("/donors", async (req, res) => {
    const { bloodGroup, district, upazila } = req.query;

    const query = { role: "donor", status: "active" };
    if (bloodGroup) query.bloodGroup = bloodGroup;
    if (district) query.district = district;
    if (upazila) query.upazila = upazila;

    const donors = await usersCollection.find(query).sort({ createdAt: -1 }).toArray();
    res.send(donors);
  });

  // ---------------- ADMIN USERS ----------------
  app.get("/admin/users", verifyJWT, verifyAdmin, async (req, res) => {
    const status = req.query.status;
    const query = status ? { status } : {};
    const users = await usersCollection.find(query).sort({ createdAt: -1 }).toArray();
    res.send(users);
  });

  app.patch("/admin/users/:id/role", verifyJWT, verifyAdmin, async (req, res) => {
    const { role } = req.body || {};
    if (!["donor", "volunteer", "admin"].includes(role)) {
      return res.status(400).send({ message: "Invalid role" });
    }
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { role, updatedAt: new Date() } }
    );
    res.send(result);
  });

  app.patch("/admin/users/:id/status", verifyJWT, verifyAdmin, async (req, res) => {
    const { status } = req.body || {};
    if (!["active", "blocked"].includes(status)) {
      return res.status(400).send({ message: "Invalid status" });
    }
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status, updatedAt: new Date() } }
    );
    res.send(result);
  });

  // ---------------- DONATION REQUESTS ----------------

  // ✅ PUBLIC LIST (FIXED): supports ?status=pending&page=1&limit=12
  app.get("/donation-requests", async (req, res) => {
    try {
      const { status = "pending", page = 1, limit = 12 } = req.query;

      const query = {};
      if (status) query.status = status;

      const skip = (Number(page) - 1) * Number(limit);

      const col = await getRequestsCollection();

      const [items, total] = await Promise.all([
        col.find(query).sort({ createdAt: -1 }).skip(skip).limit(Number(limit)).toArray(),
        col.countDocuments(query),
      ]);

      res.send({ items, total });
    } catch (e) {
      res.status(500).send({ message: "Server error", error: e.message });
    }
  });

  app.get("/donation-requests/:id", verifyJWT, async (req, res) => {
    const col = await getRequestsCollection();
    const item = await col.findOne({ _id: new ObjectId(req.params.id) });
    if (!item) return res.status(404).send({ message: "Not found" });
    res.send(item);
  });

  app.post("/donation-requests", verifyJWT, verifyNotBlocked, async (req, res) => {
    const email = normalizeEmail(req.decoded.email);
    const me = await getDBUser(email);

    const data = req.body || {};
    const doc = {
      requesterName: data.requesterName || me?.name || "",
      requesterEmail: email,
      recipientName: data.recipientName || "",
      recipientDistrict: data.recipientDistrict || "",
      recipientUpazila: data.recipientUpazila || "",
      hospitalName: data.hospitalName || "",
      fullAddress: data.fullAddress || "",
      bloodGroup: data.bloodGroup || "",
      donationDate: data.donationDate || "",
      donationTime: data.donationTime || "",
      requestMessage: data.requestMessage || "",
      status: "pending",
      donorName: "",
      donorEmail: "",
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const col = await getRequestsCollection();
    const result = await col.insertOne(doc);
    res.status(201).send({ insertedId: result.insertedId });
  });

  app.get("/donation-requests/my-recent", verifyJWT, async (req, res) => {
    const email = normalizeEmail(req.decoded.email);
    const col = await getRequestsCollection();
    const items = await col.find({ requesterEmail: email }).sort({ createdAt: -1 }).limit(3).toArray();
    res.send(items);
  });

  app.get("/donation-requests/my", verifyJWT, async (req, res) => {
    const email = normalizeEmail(req.decoded.email);
    const { status, page = 1, limit = 10 } = req.query;

    const query = { requesterEmail: email };
    if (status) query.status = status;

    const skip = (Number(page) - 1) * Number(limit);
    const col = await getRequestsCollection();

    const [items, total] = await Promise.all([
      col.find(query).sort({ createdAt: -1 }).skip(skip).limit(Number(limit)).toArray(),
      col.countDocuments(query),
    ]);

    res.send({ items, total });
  });

  app.get("/admin/donation-requests", verifyJWT, verifyVolunteerOrAdmin, async (req, res) => {
    const { status, page = 1, limit = 10 } = req.query;
    const query = {};
    if (status) query.status = status;

    const skip = (Number(page) - 1) * Number(limit);
    const col = await getRequestsCollection();

    const [items, total] = await Promise.all([
      col.find(query).sort({ createdAt: -1 }).skip(skip).limit(Number(limit)).toArray(),
      col.countDocuments(query),
    ]);

    res.send({ items, total });
  });

  app.patch("/donation-requests/:id/donate", verifyJWT, verifyNotBlocked, async (req, res) => {
    const email = normalizeEmail(req.decoded.email);
    const me = await getDBUser(email);

    const col = await getRequestsCollection();
    const existing = await col.findOne({ _id: new ObjectId(req.params.id) });
    if (!existing) return res.status(404).send({ message: "Not found" });
    if (existing.status !== "pending") return res.status(400).send({ message: "Only pending can be donated" });

    await col.updateOne(
      { _id: existing._id },
      {
        $set: {
          status: "inprogress",
          donorName: me?.name || "",
          donorEmail: email,
          updatedAt: new Date(),
        },
      }
    );

    res.send({ success: true });
  });

  app.patch("/donation-requests/:id/status", verifyJWT, verifyNotBlocked, async (req, res) => {
    const email = normalizeEmail(req.decoded.email);
    const me = await getDBUser(email);
    const { status } = req.body || {};

    if (!["pending", "inprogress", "done", "canceled"].includes(status)) {
      return res.status(400).send({ message: "Invalid status" });
    }

    const col = await getRequestsCollection();
    const existing = await col.findOne({ _id: new ObjectId(req.params.id) });
    if (!existing) return res.status(404).send({ message: "Not found" });

    const isAdminOrVol = ["admin", "volunteer"].includes(me?.role);

    if (!isAdminOrVol) {
      if (normalizeEmail(existing.donorEmail) !== email) {
        return res.status(403).send({ message: "Forbidden" });
      }
      if (existing.status !== "inprogress") {
        return res.status(400).send({ message: "Donor can change only from inprogress" });
      }
      if (!["done", "canceled"].includes(status)) {
        return res.status(400).send({ message: "Donor can only set done/canceled" });
      }
    }

    const result = await col.updateOne(
      { _id: existing._id },
      { $set: { status, updatedAt: new Date() } }
    );

    res.send(result);
  });

  app.delete("/donation-requests/:id", verifyJWT, verifyNotBlocked, async (req, res) => {
    const email = normalizeEmail(req.decoded.email);
    const me = await getDBUser(email);

    const col = await getRequestsCollection();
    const existing = await col.findOne({ _id: new ObjectId(req.params.id) });
    if (!existing) return res.status(404).send({ message: "Not found" });

    const isOwner = normalizeEmail(existing.requesterEmail) === email;
    const isAdmin = me?.role === "admin";
    if (!isOwner && !isAdmin) return res.status(403).send({ message: "Forbidden" });

    const result = await col.deleteOne({ _id: existing._id });
    res.send(result);
  });

  // ---------------- FUNDINGS ----------------
  app.post("/fundings", verifyJWT, verifyNotBlocked, async (req, res) => {
    const email = normalizeEmail(req.decoded.email);
    const me = await getDBUser(email);

    const amount = Number(req.body?.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).send({ message: "Valid amount required" });
    }

    const doc = {
      amount,
      name: me?.name || "User",
      email,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await fundingsCollection.insertOne(doc);
    res.status(201).send({ insertedId: result.insertedId });
  });

  app.get("/fundings", verifyJWT, async (req, res) => {
    const email = normalizeEmail(req.decoded.email);
    const me = await getDBUser(email);

    const query = me?.role === "admin" ? {} : { email };
    const items = await fundingsCollection.find(query).sort({ createdAt: -1 }).toArray();
    res.send(items);
  });

  // ---------------- ADMIN STATS ----------------
  app.get("/admin/stats", verifyJWT, verifyVolunteerOrAdmin, async (req, res) => {
    const col = await getRequestsCollection();

    const [totalDonors, totalRequests] = await Promise.all([
      usersCollection.countDocuments({ role: "donor" }),
      col.countDocuments({}),
    ]);

    const fundAgg = await fundingsCollection
      .aggregate([{ $group: { _id: null, totalFunding: { $sum: "$amount" } } }])
      .toArray();

    res.send({
      totalUsers: totalDonors,
      totalDonationRequest: totalRequests,
      totalFunding: fundAgg?.[0]?.totalFunding || 0,
    });
  });
}

run().catch((e) => console.error("❌ run() error:", e.message));

app.use((err, req, res, next) => {
  console.error("❌ Server error:", err.message);
  res.status(500).send({ message: err.message || "Server error" });
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`✅ Local server running on http://localhost:${port}`);
});
