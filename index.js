const express = require("express");
const multer = require("multer");
const bcrypt = require("bcrypt");
const passwordValidator = require("password-validator");
const fs = require("fs");
const nodemailer = require("nodemailer");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const Razorpay = require("razorpay");
const path = require("path");
const { isoUint8Array, isoBase64URL } = require('@simplewebauthn/server/helpers');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require("@simplewebauthn/server");

require("dotenv").config();

const SessionModel = require('./models/SessionModel');
const MongoStore = require("connect-mongo");
const crypto = require("crypto");
const generateSecretKey = require('./helpers/generateSecretKey')

const Maincategory = require("./models/Maincategory");
const Subcategory = require("./models/Subcategory");
const Brand = require("./models/Brand");
const Product = require("./models/Product");
const User = require("./models/User");
const Cart = require("./models/Cart");
const Wishlist = require("./models/Wishlist");
const Checkout = require("./models/Checkout");
const Contact = require("./models/Contact");
const Newslatter = require("./models/Newslatter");
const isProduction = process.env.NODE_ENV === "production";
const frontendUrl =
  process.env.NODE_ENV === "production"
    ? "https://liveshop-front.vercel.app" // Vercel frontend URL for production
    : "http://localhost:3000";

const allowedOrigins = [
  frontendUrl, // The correct URL for the frontend
  'http://localhost:3000', // Local development
];

require("./dbConnect");
const app = express();
app.use(express.json({ limit: '10mb' }));  // Increase payload size limit
app.use(express.urlencoded({ limit: '10mb', extended: true }));

const corsOptions = {
  origin: ["https://liveshop-front.vercel.app", "http://localhost:3000"],
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "Accept", "username"],
  credentials: true, // Allow credentials like cookies and tokens
};
app.use(cors(corsOptions));
// 
app.options("*", cors(corsOptions));

app.use(express.json());
app.use(express.static(path.join(__dirname, "build")));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));


// app.use(
//   session({
//     secret: process.env.SESSION_SECRET, // This can be hardcoded for now, but ensure it's secure.
//     resave: false, // Prevent session resave if nothing changes.
//     saveUninitialized: false, // Set to true to save empty sessions during testing.
//     store: MongoStore.create({
//       mongoUrl: process.env.MONGODB_URL, // Use your testing MongoDB instance.
//       collectionName: "sessions", // The sessions will be stored in the 'sessions' collection.
//       ttl: 14 * 24 * 60 * 60, // Session TTL set to 14 days (for testing, this is fine).
//     }),
//     cookie: {
//       secure: true, // Secure should be true only in production with HTTPS.
//       httpOnly: true,       // This ensures the cookie is not accessible via client-side JS.
//       maxAge: 1000 * 60 * 15, // 15-minute expiration.
//       sameSite: 'None', // 'None' for cross-site cookies in production, 'Lax' for development.
//     },
//   })
// );
// app.use(
//   session({
//     secret: process.env.SESSION_SECRET, // This can be hardcoded for now, but ensure it's secure.
//     resave: false, // Prevent session resave if nothing changes.
//     saveUninitialized: false, // Set to true to save empty sessions during testing.
//     store: MongoStore.create({
//       mongoUrl: process.env.MONGODB_URL, // Use your testing MongoDB instance.
//       collectionName: "sessions", // The sessions will be stored in the 'sessions' collection.
//       ttl: 14 * 24 * 60 * 60, // Session TTL set to 14 days (for testing, this is fine).
//     }),
//     cookie: {
//       secure: false, // Secure should be true only in production with HTTPS.
//       httpOnly: true,       // This ensures the cookie is not accessible via client-side JS.
//       maxAge: 1000 * 60 * 15, // 15-minute expiration.
//       sameSite: 'Lax', // 'None' for cross-site cookies in production, 'Lax' for development.
//     },
//   })
// );

console.log("NODE_ENV after session--->", process.env.NODE_ENV);
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads");
  },
  filename: function (req, file, cb) {
    const uniqueName = Date.now() + "-" + encodeURIComponent(file.originalname);
    cb(null, uniqueName);
  },
});

const upload = multer({ storage: storage, limits: { fileSize: 10 * 1024 * 1024 }, });

var schema = new passwordValidator();
schema
  .is()
  .min(8) // Minimum length 8
  .is()
  .max(100) // Maximum length 100
  .has()
  .uppercase(1) // Must have uppercase letters
  .has()
  .lowercase(1) // Must have lowercase letters
  .has()
  .digits(1) // Must have at least 2 digits
  .has()
  .not()
  .spaces() // Should not have spaces
  .is()
  .not()
  .oneOf(["Password@123", "Password123", "Admin@123", "Admin123", "User@123"]);

const from = process.env.MAILSENDER;
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  requireTLS: true,
  auth: {
    user: from,
    pass: process.env.PASSWORD,
  },
});

async function verifyToken(req, res, next) {
  try {
    const token = req.headers.authorization && req.headers.authorization.split(" ")[1];
    const username = req.headers.username; // Username required for general user checks

    if (!token || !username) {
      return res.status(401).json({
        result: "Fail",
        message: "Authorization token or username is missing",
      });
    }

    const decoded = jwt.verify(token, process.env.USERSAULTKEY); // Use general user secret key
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ result: "Fail", message: "User not found" });
    }

    req.user = user; // Attach user to request
    req.token = token;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        result: "Fail",
        message: "Session expired, please log in again",
      });
    } else if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        result: "Fail",
        message: "Invalid token, please log in again",
      });
    }
    res.status(500).json({ result: "Fail", message: "Internal Server Error" });
  }
}


async function verifyAdmin(req, res, next) {
  try {
    const token = req.headers.authorization && req.headers.authorization.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        result: "Fail",
        message: "Authorization token is missing",
      });
    }

    const decoded = jwt.verify(token, process.env.ADMINSAULTKEY); // Admin secret key
    const user = await User.findById(decoded.id); // Get user based on ID from token

    if (!user || user.role !== "Admin") {
      return res.status(403).json({
        result: "Fail",
        message: "You are not authorized to access this resource",
      });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        result: "Fail",
        message: "Session expired, please log in again",
      });
    } else if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        result: "Fail",
        message: "Invalid token, please log in again",
      });
    }
    res.status(500).json({ result: "Fail", message: "Internal Server Error" });
  }
}


//Payment API
app.post("/orders", verifyToken, async (req, res) => {
  try {
    const instance = new Razorpay({
      key_id: process.env.RPKEYID,
      key_secret: process.env.RPSECRETKEY,
    });

    const options = {
      amount: req.body.amount * 100,
      currency: "INR",
    };

    instance.orders.create(options, (error, order) => {
      if (error) {
        console.log(error);
        return res.status(500).json({ message: "Something Went Wrong!" });
      }
      res.status(200).json({ data: order });
    });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error!" });
    console.log(error);
  }
});
// url is changed from verify to payment-verify
app.put("/payment-verify", verifyToken, async (req, res) => {
  try {
    var check = await Checkout.findOne({ _id: req.body.checkid });
    check.rppid = req.body.razorpay_payment_id;
    check.paymentstatus = "Done";
    check.paymentmode = "Net Banking";
    await check.save();
    var user = await User.findOne({ _id: check.userid });
    let mailOption = {
      from: process.env.MAILSENDER,
      to: user.email,
      subject: "Payment Done !!! : Team LiveShop",
      text: `Thanks to Shop with Us\nYour Payment is Confirmed\nTrack Order in Profile Section!!!\nTeam LiveShop`,
    };
    transporter.sendMail(mailOption, (error, data) => {
      if (error) console.log(error);
    });
    res.status(200).send({ result: "Done" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal Server Error!" });
  }
});

//API for maincategory
app.post("/create-maincategory", verifyAdmin, async (req, res) => {
  try {

    var data = new Maincategory(req.body);
    await data.save();
    res.send({ result: "Done", message: "Maincategory is Created!!!!!" });
  } catch (error) {
    if (error.keyValue)
      res
        .status(401)
        .send({ result: "Fail", message: "Maincategory Name Must be Unique" });
    else if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/get-maincategory", async (req, res) => {
  try {
    var data = await Maincategory.find();
    res.status(200).json({ result: "Done", data: data });
  } catch (error) {
    console.log("error", error)
    res.status(500).json({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/get-single-maincategory/:_id", async (req, res) => {
  try {
    var data = await Maincategory.findOne({ _id: req.params._id });
    if (data) res.send({ result: "Done", data: data });
    else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.put("/maincategory/:_id", verifyAdmin, async (req, res) => {
  try {
    var data = await Maincategory.findOne({ _id: req.params._id });
    if (data) {
      data.name = req.body.name;
      await data.save();
      res.send({ result: "Done", message: "Record is Updated!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    if (error.keyValue)
      res
        .status(401)
        .send({ result: "Fail", message: "Maincategory Name Must be Unique" });
    else if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.delete("/delete-maincategory/:_id", verifyAdmin, async (req, res) => {
  try {
    var data = await Maincategory.findOne({ _id: req.params._id });
    if (data) {
      await data.delete();
      res.send({ result: "Done", message: "Record is Deleted!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});

//API for subcategory
app.post("/create-subcategory", verifyAdmin, async (req, res) => {
  try {
    var data = new Subcategory(req.body);
    await data.save();
    res.send({ result: "Done", message: "Subcategory is Created!!!!!" });
  } catch (error) {
    if (error.keyValue)
      res
        .status(401)
        .send({ result: "Fail", message: "Subcategory Name Must be Unique" });
    else if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/get-all-subcategory", async (req, res) => {
  try {
    var data = await Subcategory.find();
    res.send({ result: "Done", data: data });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/get-single-subcategory/:_id", async (req, res) => {
  try {
    var data = await Subcategory.findOne({ _id: req.params._id });
    if (data) res.send({ result: "Done", data: data });
    else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.put("/update-subcategory/:_id", verifyAdmin, async (req, res) => {
  try {
    var data = await Subcategory.findOne({ _id: req.params._id });
    if (data) {
      data.name = req.body.name;
      await data.save();
      res.send({ result: "Done", message: "Record is Updated!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    if (error.keyValue)
      res
        .status(401)
        .send({ result: "Fail", message: "Subcategory Name Must be Unique" });
    else if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.delete("/delete-subcategory/:_id", verifyAdmin, async (req, res) => {
  try {
    var data = await Subcategory.findOne({ _id: req.params._id });
    if (data) {
      await data.delete();
      res.send({ result: "Done", message: "Record is Deleted!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});

//API for brand
app.post("/create-brand", verifyAdmin, async (req, res) => {
  try {
    var data = new Brand(req.body);
    await data.save();
    res.send({ result: "Done", message: "Brand is Created!!!!!" });
  } catch (error) {
    if (error.keyValue)
      res
        .status(401)
        .send({ result: "Fail", message: "Brand Name Must be Unique" });
    else if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/get-all-brand", async (req, res) => {
  try {
    var data = await Brand.find();
    res.send({ result: "Done", data: data });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/get-single-brand/:_id", async (req, res) => {
  try {
    var data = await Brand.findOne({ _id: req.params._id });
    if (data) res.send({ result: "Done", data: data });
    else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.put("/update-brand/:_id", verifyAdmin, async (req, res) => {
  try {
    var data = await Brand.findOne({ _id: req.params._id });
    if (data) {
      data.name = req.body.name;
      await data.save();
      res.send({ result: "Done", message: "Record is Updated!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    if (error.keyValue)
      res
        .status(401)
        .send({ result: "Fail", message: "Brand Name Must be Unique" });
    else if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.delete("/delete-brand/:_id", verifyAdmin, async (req, res) => {
  try {
    var data = await Brand.findOne({ _id: req.params._id });
    if (data) {
      await data.delete();
      res.send({ result: "Done", message: "Record is Deleted!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});

//API for Product
app.post('/create-product', upload.fields([
  { name: 'pic1', maxCount: 1 },
  { name: 'pic2', maxCount: 1 },
  { name: 'pic3', maxCount: 1 },
  { name: 'pic4', maxCount: 1 },
]), async (req, res) => {
  try {
    // Handle text data and file upload data
    const productData = req.body;  // This will contain text fields like name, category, etc.
    const productImages = req.files;  // This will contain files

    const newProduct = {
      name: productData.name,
      maincategory: productData.maincategory,
      subcategory: productData.subcategory,
      brand: productData.brand,
      color: productData.color,
      size: productData.size,
      baseprice: productData.baseprice,
      discount: productData.discount,
      finalprice: productData.finalprice,
      stock: productData.stock,
      description: productData.description,
      pic1: productImages.pic1[0].filename,
      pic2: productImages.pic2[0].filename,
      pic3: productImages.pic3[0].filename,
      pic4: productImages.pic4[0].filename,
    };

    // Save the new product to the database (your save logic here)
    res.status(201).send({ result: "Done", message: "Product created successfully!" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});

app.get("/get-all-product", async (req, res) => {
  try {
    var data = await Product.find();
    res.send({ result: "Done", data: data });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/get-single-product/:_id", async (req, res) => {
  try {
    var data = await Product.findOne({ _id: req.params._id });
    if (data) res.send({ result: "Done", data: data });
    else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.put(
  "/update-product/:_id",
  upload.fields([
    { name: "pic1", maxCount: 1 },
    { name: "pic2", maxCount: 2 },
    { name: "pic3", maxCount: 3 },
    { name: "pic4", maxCount: 4 },
  ]),
  verifyToken,
  async (req, res) => {
    try {
      var data = await Product.findOne({ _id: req.params._id });
      if (data) {
        data.name = req.body.name ?? data.name;
        data.maincategory = req.body.maincategory ?? data.maincategory;
        data.subcategory = req.body.subcategory ?? data.subcategory;
        data.brand = req.body.brand ?? data.brand;
        data.color = req.body.color ?? data.color;
        data.size = req.body.size ?? data.size;
        data.baseprice = req.body.baseprice ?? data.baseprice;
        data.discount = req.body.discount ?? data.discount;
        data.finalprice = req.body.finalprice ?? data.finalprice;
        data.stock = req.body.stock ?? data.stock;
        data.description = req.body.description ?? data.description;
        if (req.files && req.files.pic1) {
          try {
            fs.unlink("./public/uploads/" + data.pic1, () => { });
          } catch (error) {
            console.log(error);
          }
          data.pic1 = req.files.pic1[0].filename;
        }
        if (req.files && req.files.pic2) {
          try {
            fs.unlink("./public/uploads/" + data.pic2, () => { });
          } catch (error) { }
          data.pic2 = req.files.pic2[0].filename;
        }
        if (req.files && req.files.pic3) {
          try {
            fs.unlink("./public/uploads/" + data.pic3, () => { });
          } catch (error) { }
          data.pic3 = req.files.pic3[0].filename;
        }
        if (req.files && req.files.pic4) {
          try {
            fs.unlink("./public/uploads/" + data.pic4, () => { });
          } catch (error) { }
          data.pic4 = req.files.pic4[0].filename;
        }
        await data.save();
        res.send({ result: "Done", message: "Record is Updated!!!!!" });
      } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
    } catch (error) {
      if (error.errors.name)
        res
          .status(401)
          .send({ result: "Fail", message: error.errors.name.message });
      else if (error.errors.maincategory)
        res
          .status(401)
          .send({ result: "Fail", message: error.errors.maincategory.message });
      else if (error.errors.subcategory)
        res
          .status(401)
          .send({ result: "Fail", message: error.errors.subcategory.message });
      else if (error.errors.brand)
        res
          .status(401)
          .send({ result: "Fail", message: error.errors.brand.message });
      else if (error.errors.color)
        res
          .status(401)
          .send({ result: "Fail", message: error.errors.color.message });
      else if (error.errors.size)
        res
          .status(401)
          .send({ result: "Fail", message: error.errors.size.message });
      else if (error.errors.baseprice)
        res
          .status(401)
          .send({ result: "Fail", message: error.errors.baseprice.message });
      else if (error.errors.finalprice)
        res
          .status(401)
          .send({ result: "Fail", message: error.errors.finalprice.message });
      else
        res
          .status(500)
          .send({ result: "Fail", message: "Internal Server Error" });
    }
  }
);
app.delete("/delete-product/:_id", verifyToken, async (req, res) => {
  try {
    var data = await Product.findOne({ _id: req.params._id });
    if (data) {
      try {
        fs.unlink("./public/uploads/" + data.pic1, () => { });
      } catch (error) { }
      try {
        fs.unlink("./public/uploads/" + data.pic2, () => { });
      } catch (error) { }
      try {
        fs.unlink("./public/uploads/" + data.pic3, () => { });
      } catch (error) { }
      try {
        fs.unlink("./public/uploads/" + data.pic4, () => { });
      } catch (error) { }
      await data.delete();
      res.send({ result: "Done", message: "Record is Deleted!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
//API for User
app.post("/create-user", async (req, res) => {
  try {
    const { name, username, phone, email, password } = req.body;

    if (!name || !username || !phone || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required"
      });
    }

    const existingUser = await User.findOne({ username });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: " User already exists"
      });
    };

    const hashedPassword = await bcrypt.hash(password, 12)

    const newUser = await new User({
      name, username, phone, email, password: hashedPassword
    });

    const result = await newUser.save();

    return res.status(201).json({
      status: true,
      message: "User successfully created",
      data: result
    })

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    })
  }
});
app.get("/user", async (req, res) => {
  try {
    var data = await User.find();
    res.send({ result: "Done", data: data });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/user/:_id", async (req, res) => {
  try {
    var data = await User.findOne({ _id: req.params._id });
    if (data) res.send({ result: "Done", data: data });
    else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.put("/user/:_id", upload.single("pic"), async (req, res) => {
  try {
    // Find the user by ID
    const user = await User.findOne({ _id: req.params._id });

    if (!user) {
      return res.status(404).send({ result: "Fail", message: "Invalid ID" });
    }

    // Update fields if present in the request
    user.name = req.body.name ?? user.name;
    user.email = req.body.email ?? user.email;
    user.phone = req.body.phone ?? user.phone;
    user.addressline1 = req.body.addressline1 ?? user.addressline1;
    user.addressline2 = req.body.addressline2 ?? user.addressline2;
    user.addressline3 = req.body.addressline3 ?? user.addressline3;
    user.pin = req.body.pin ?? user.pin;
    user.city = req.body.city ?? user.city;
    user.state = req.body.state ?? user.state;

    // If a new profile picture is uploaded, handle file replacement
    if (req.file) {
      // Remove the old picture if it exists
      if (user.pic) {
        const oldPicPath = path.join(__dirname, "public/uploads/", user.pic);
        fs.unlink(oldPicPath, (err) => {
          if (err) {
            console.error(
              `Failed to delete old profile picture: ${err.message}`
            );
          }
        });
      }

      // Update the user's profile picture
      user.pic = req.file.filename;
    }

    // Save the updated user data
    await user.save();
    res.send({ result: "Done", message: "Record is Updated!" });
  } catch (error) {
    console.error("Error updating user:", error);

    // Handle validation errors
    if (error.keyValue) {
      return res
        .status(401)
        .send({ result: "Fail", message: "User Name Must be Unique" });
    } else if (error.errors) {
      const errorMessages = Object.values(error.errors).map(
        (err) => err.message
      );
      return res
        .status(401)
        .send({ result: "Fail", message: errorMessages.join(", ") });
    } else {
      // General error handling
      return res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
    }
  }
});

app.delete("/user/:_id", verifyAdmin, async (req, res) => {
  try {
    var data = await User.findOne({ _id: req.params._id });
    if (data) {
      try {
        fs.unlink("./public/uploads/" + data.pic, () => { });
      } catch (error) { }
      await data.delete();
      res.send({ result: "Done", message: "Record is Deleted!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
//api for login
app.post("/login", async (req, res) => {
  try {
    // Find user by username
    const user = await User.findOne({ username: req.body.username });

    if (!user) {
      return res
        .status(404)
        .send({ result: "Fail", message: "Invalid Username or Password" });
    }

    // Check if the password matches
    const passwordMatch = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!passwordMatch) {
      return res
        .status(404)
        .send({ result: "Fail", message: "Invalid Username or Password" });
    }

    const secretKey = generateSecretKey(user.role);

    // Check if the secret key exists
    if (!secretKey) {
      throw new Error("Secret key is not defined. Check environment variables.");
    }

    // Sign JWT token
    const token = jwt.sign({ id: user._id }, secretKey);

    // Check if the tokens array length is less than 3 (optional logic)
    if (user.tokens.length < 3) {
      user.tokens.push(token); // Add the new token
      await user.save(); // Save user with new token

      res.send({ result: "Done", data: user, token: token });
    } else {
      res.status(401).send({
        result: "Fail",
        message:
          "You are already logged in from 3 devices. Please log out from another device to log in here.",
      });
    }
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});

//WebAuth N API

app.post("/register-webauthn/start", async (req, res) => {
  try {
    const { username } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).send({ result: "fail", message: "User not found" });
    }

    // Convert user id into base64URL format for WebAuthn support
    const userID = isoUint8Array.fromUTF8String(user._id.toString());

    const origin = req.headers.origin;
    console.log("Origin", origin)
    const RPID = process.env.NODE_ENV === 'production' ? "liveshop-front.vercel.app" : 'localhost';

    // Generate WebAuthn registration options with userID in base64URL and challenge
    const options = await generateRegistrationOptions({
      rpName: "LiveShop",
      rpID: RPID,
      userID: userID,
      userName: username,
      attestationType: "none",
      allowCredentials: [],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',  // Use platform authenticator (e.g., Face ID, Touch ID)
        userVerification: 'preferred',  // Allow biometric authentication
        residentKey: 'discouraged',
      },
      excludeCredentials: user.webAuthnCredentials.map(cred => ({
        id: cred.credentialId,
        type: 'public-key',
        transports: ['internal']
      })),
      supportedAlgorithmIDs: [-7, -257],
    });
    console.log("Generated WebAuthn options:", options);
    // Save the challenge and userID in the session with expiry
    const sessionData = {
      challenge: options.challenge,
      userID: userID,  // base64URL-encoded user ID
      expires: Date.now() + 5 * 60 * 1000,  // 5 minutes expiry
    };

    // Save the session in MongoDB using the custom session model
    const session = new SessionModel({ data: sessionData });
    await session.save();

    // Use the MongoDB-generated _id as the sessionID
    const sessionID = session._id;

    console.log("Session stored in MongoDB:", session);

    // Send the sessionID and WebAuthn options as the response
    return res.status(200).json({ options, sessionID });
  } catch (error) {
    console.error("Error during WebAuthN registration start:", error);
    res.status(500).send({ result: "fail", message: "Internal Server Error during registration start" });
  }
});

app.post("/register-webauthn/verify", async (req, res) => {
  try {
    const { sessionID, username, attestationResponse } = req.body;

    const session = await SessionModel.findOne({ sessionID });

    if (!session || !session.data.challenge) {
      return res.status(400).send({ result: "fail", message: "Session expired or invalid." });
    }

    // Verify session expiry
    if (session.data.expires < Date.now()) {
      return res.status(400).send({ result: "fail", message: "Session expired." });
    }

    const expectedChallenge = session.data.challenge;
    const expectedOrigin = process.env.NODE_ENV === "production"
      ? "https://liveshop-front.vercel.app"
      : "http://localhost:3000";
    const expectedRPID = process.env.NODE_ENV === 'production'
      ? "liveshop-front.vercel.app"
      : 'localhost';


    // Proceed with WebAuthn verification process
    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge: expectedChallenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: expectedRPID,
      supportedAlgorithmIDs: [-7, -257],  // Algorithm support
      requireUserVerification: false
    });

    if (verified && registrationInfo) {
      // Save credentials in user model
      const user = await User.findOne({ username });

      // Ensure credentialID is present in registrationInfo
      const { credentialID, credentialPublicKey, counter } = registrationInfo;

      if (!credentialID) {
        throw new Error("Missing credentialID in registrationInfo");
      };

      // Push new credentials to the user's WebAuthn credentials
      user.webAuthnCredentials.push({
        credentialId: registrationInfo.credentialID, // This should be the credential ID from WebAuthn
        publicKey: isoBase64URL.fromBuffer(registrationInfo.credentialPublicKey),
        signCount: registrationInfo.counter,
        deviceType: registrationInfo.credentialDeviceType,
        backedUp: registrationInfo.credentialBackedUp,
        transports: attestationResponse.transports || [],  // Handle transports if applicable
      });

      await user.save();

      res.send({ result: "Done", message: "WebAuthn credentials registered successfully" });
    } else {
      return res.status(400).send({ result: "fail", message: "WebAuthn registration verification failed." });
    }

  } catch (error) {
    console.error("Error during WebAuthN registration verification:", error);
    return res.status(500).send({ result: "fail", message: "Internal Server Error during verification." });
  }
});

// WebAuthn Login Start
app.post("/webauthn/login", async (req, res) => {
  try {
    const { sessionID, username } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      return res
        .status(404)
        .send({ result: "Fail", message: "User not found" });
    }

    // Check if the user has any WebAuthn credentials
    if (!user.webAuthnCredentials || user.webAuthnCredentials.length === 0) {
      return res.status(404).send({
        result: "Fail",
        message: "No WebAuthn credentials found for this user",
      });
    }
    const RPID = process.env.NODE_ENV === 'production'
      ? "liveshop-front.vercel.app"
      : 'localhost';


    const options = await generateAuthenticationOptions({
      rpID: RPID,
      allowCredentials: user.webAuthnCredentials.map((cred) => ({
        id: cred.credentialId,
        type: "public-key",
        transports: ["internal"],
      })),
      userVerification: "preferred",
    });

    const session = await SessionModel.findById(sessionID);
    if (!session) {
      return res.status(400).send({ result: "fail", message: "Invalid session ID" });
    };

    session.data.challenge = options.challenge;
    session.data.expires = Date.now() + 5 * 60 * 1000; // Extend expiry by 5 minutes
    await session.save();

    console.log("Updated session with challenge:", session);

    // Send the WebAuthn options and sessionID to the client
    return res.status(200).json({ options, sessionID });
  } catch (error) {
    console.error("Error during WebAuthN login start:", error.message);
    res.status(500).send({
      result: "fail",
      message: "Internal Server Error during login start",
    });
  }
});

app.post("/login-webauthn/verify", async (req, res) => {
  try {
    const { username, authResponse, sessionID  } = req.body;

    // Find user in the database
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).send({ result: "Fail", message: "User not found" });
    }

    const session = await SessionModel.findById(sessionID);
    if (!session) {
      return res.status(400).send({ result: "Fail", message: "Invalid session ID" });
    };


    // Check if session contains challenge
    const expectedChallenge = session.data.challenge;
    if (!expectedChallenge) {
      return res.status(400).send({ result: "Fail", message: "Challenge missing or session expired" });
    }

    // Find user's WebAuthn credentials
    const credential = user.webAuthnCredentials.find(
      (cred) => cred.credentialId === authResponse.id
    );
    if (!credential) {
      return res.status(404).send({ result: "Fail", message: "Credentials not found" });
    }

    // Define expected origin and RPID based on environment
    const expectedOrigin = process.env.NODE_ENV === "production"
      ? "https://liveshop-front.vercel.app"
      : "http://localhost:3000";
    const expectedRPID = process.env.NODE_ENV === "production"
      ? "liveshop-front.vercel.app"
      : "localhost";;

    // Verify the WebAuthn authentication response
    const { verified, authenticationInfo } = await verifyAuthenticationResponse({
      response: authResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator: {
        counter: credential.counter,
        credentialPublicKey: isoBase64URL.toBuffer(credential.publicKey),
      },
      requireUserVerification: false,
    });

    if (verified) {
      // Update the counter in the database to prevent replay attacks
      credential.counter = authenticationInfo.newCounter;
      await user.save();

      // Clear the challenge from session after verification
      delete session.data.challenge; // Clear challenge
      await session.save();

      const secretKey = generateSecretKey(user.role);

      // Generate a JWT token upon successful login
      const token = jwt.sign({ id: user._id }, secretKey);

      // Token storage logic (similar to the normal login flow)
      if (user.tokens.length < 3) {
        user.tokens.push(token); // Add the new token
        await user.save(); // Save user with the new token

        // Send the token back to the client
        res.send({ result: "Done", token: token, verified: verified, data: user });
      } else {
        // Token limit reached, deny login
        res.status(401).send({
          result: "Fail",
          message:
            "You are already logged in from 3 devices. Please log out from another device to log in here.",
        });
      }
    } else {
      res.status(400).send({ result: "Fail", message: "Authentication failed" });
    }
  } catch (error) {
    console.error("Error during WebAuthN login verification:", error);
    res.status(500).send({ result: "fail", message: "Internal Server Error during login verification" });
  }
});

//api for logout
// Logout from a single session
app.post("/logout", async (req, res) => {
  try {
    const { username, token, sessionID } = req.body;

    // Ensure both token, username, and sessionID exist
    if (!token || !username || !sessionID) {
      return res.status(400).json({
        result: "Fail",
        message: "Token, session ID, or username is missing",
      });
    }

    // Find the user by username
    let user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ result: "Fail", message: "User not found" });
    }

    // Find and remove the token from the user's tokens array
    const tokenIndex = user.tokens.findIndex((item) => item === token);
    if (tokenIndex === -1) {
      return res.status(401).json({
        result: "Fail",
        message: "Token not found or already logged out",
      });
    }
    user.tokens.splice(tokenIndex, 1);
    await user.save();

    // Clear the session from the database
    await SessionModel.findByIdAndDelete(sessionID);

    res.status(200).send({ result: "Done", message: "You have logged out successfully and session cleared" });
  } catch (error) {
    console.error("Logout Error:", error);
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});


// Logout from all sessions
app.post("/logoutall", async (req, res) => {
  try {
    const { username, token } = req.body
    // Ensure username exists
    if (!username) {
      return res.status(400).json({
        result: "Fail",
        message: "Username is missing",
      });
    }

    // Find the user by username
    let user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ result: "Fail", message: "User not found" });
    }

    // Clear all tokens
    user.tokens = [];
    await user.save();

    res.status(200).send({ result: "Done", message: "You have been logged out from all devices" });
  } catch (error) {
    console.error("Logout All Error:", error);
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});


//API for Cart
app.post("/cart", verifyToken, async (req, res) => {
  try {
    var data = new Cart(req.body);
    await data.save();
    res.send({ result: "Done", message: "Cart is Created!!!!!" });
  } catch (error) {
    if (error.errors.userid)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.userid.message });
    else if (error.errors.productid)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.productid.message });
    else if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else if (error.errors.maincategory)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.maincategory.message });
    else if (error.errors.subcategory)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.subcategory.message });
    else if (error.errors.brand)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.brand.message });
    else if (error.errors.color)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.color.message });
    else if (error.errors.size)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.size.message });
    else if (error.errors.price)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.price.message });
    else if (error.errors.total)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.total.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/cartUser/:userid", verifyToken, async (req, res) => {
  try {
    var data = await Cart.find({ userid: req.params.userid });
    res.send({ result: "Done", data: data });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/cart/:_id", verifyToken, async (req, res) => {
  try {
    var data = await Cart.findOne({ _id: req.params._id });
    if (data) res.send({ result: "Done", data: data });
    else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.put("/cart/:_id", verifyToken, async (req, res) => {
  try {
    var data = await Cart.findOne({ _id: req.params._id });
    if (data) {
      data.qty = req.body.qty;
      data.total = req.body.total;
      await data.save();
      res.send({ result: "Done", message: "Record is Updated!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    if (error.keyValue)
      res
        .status(401)
        .send({ result: "Fail", message: "Cart Name Must be Unique" });
    else if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.delete("/cart/:_id", verifyToken, async (req, res) => {
  try {
    var data = await Cart.findOne({ _id: req.params._id });
    if (data) {
      await data.delete();
      res.send({ result: "Done", message: "Record is Deleted!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.delete("/cartall/:userid", verifyToken, async (req, res) => {
  try {
    await Cart.deleteMany({ userid: req.params.userid });
    res.send({ result: "Done", message: "All Carts Are Deleted!!!!!" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});

//API for Wishlist
app.post("/wishlist", verifyToken, async (req, res) => {
  try {
    var data = new Wishlist(req.body);
    await data.save();
    res.send({ result: "Done", message: "Wishlist is Created!!!!!" });
  } catch (error) {
    if (error.errors.userid)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.userid.message });
    else if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else if (error.errors.maincategory)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.maincategory.message });
    else if (error.errors.subcategory)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.subcategory.message });
    else if (error.errors.brand)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.brand.message });
    else if (error.errors.color)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.color.message });
    else if (error.errors.size)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.size.message });
    else if (error.errors.price)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.price.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/wishlist/:userid", verifyToken, async (req, res) => {
  try {
    var data = await Wishlist.find({ userid: req.params.userid });
    if (data) res.send({ result: "Done", data: data });
    else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.delete("/wishlist/:_id", verifyToken, async (req, res) => {
  try {
    var data = await Wishlist.findOne({ _id: req.params._id });
    if (data) {
      await data.delete();
      res.send({ result: "Done", message: "Record is Deleted!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});

//API for Checkout
app.post("/checkout", verifyToken, async (req, res) => {
  try {
    var data = new Checkout(req.body);
    await data.save();
    res.send({ result: "Done", message: "Checkout is Created!!!!!" });
  } catch (error) {
    console.log(error);
    if (error.errors.userid)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.userid.message });
    else if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else if (error.errors.maincategory)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.maincategory.message });
    else if (error.errors.subcategory)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.subcategory.message });
    else if (error.errors.brand)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.brand.message });
    else if (error.errors.color)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.color.message });
    else if (error.errors.size)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.size.message });
    else if (error.errors.price)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.price.message });
    else if (error.errors.total)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.total.message });
    else if (error.errors.totalamount)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.totalamount.message });
    else if (error.errors.shippingamount)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.shippingamount.message });
    else if (error.errors.finalamount)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.finalamount.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/checkout", verifyToken, async (req, res) => {
  try {
    var data = await Checkout.find();
    res.send({ result: "Done", data: data });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/checkoutUser/:userid", verifyToken, async (req, res) => {
  try {
    var data = await Checkout.find({ userid: req.params.userid });
    res.send({ result: "Done", data: data });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/checkout/:_id", verifyToken, async (req, res) => {
  try {
    var data = await Checkout.findOne({ _id: req.params._id });
    if (data) res.send({ result: "Done", data: data });
    else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.put("/checkout/:_id", verifyToken, async (req, res) => {
  try {
    var data = await Checkout.findOne({ _id: req.params._id });
    if (data) {
      data.paymentmode = req.body.paymentmode ?? data.paymentmode;
      data.orderstatus = req.body.orderstatus ?? data.orderstatus;
      data.paymentstatus = req.body.paymentstatus ?? data.paymentstatus;
      data.rppid = req.body.rppid ?? data.rppid;
      await data.save();
      res.send({ result: "Done", message: "Record is Updated!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    if (error.keyValue)
      res
        .status(401)
        .send({ result: "Fail", message: "Checkout Name Must be Unique" });
    else if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.delete("/checkout/:_id", verifyToken, async (req, res) => {
  try {
    var data = await Checkout.findOne({ _id: req.params._id });
    if (data) {
      await data.delete();
      res.send({ result: "Done", message: "Record is Deleted!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
//API for contact
app.post("/contact", async (req, res) => {
  try {
    var data = new Contact(req.body);
    await data.save();
    res.send({
      result: "Done",
      message:
        "Thanks to Share Your Query With Us!!!! Our Team Will Contact You Soon!!!!",
    });
  } catch (error) {
    if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else if (error.errors.email)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.email.message });
    else if (error.errors.phone)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.phone.message });
    else if (error.errors.subject)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.subject.message });
    else if (error.errors.message)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.message.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/contact", verifyToken, async (req, res) => {
  try {
    var data = await Contact.find();
    res.send({ result: "Done", data: data });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/contact/:_id", verifyToken, async (req, res) => {
  try {
    var data = await Contact.findOne({ _id: req.params._id });
    if (data) res.send({ result: "Done", data: data });
    else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.put("/contact/:_id", verifyToken, async (req, res) => {
  try {
    var data = await Contact.findOne({ _id: req.params._id });
    if (data) {
      data.status = req.body.status;
      await data.save();
      res.send({ result: "Done", message: "Record is Updated!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    if (error.keyValue)
      res
        .status(401)
        .send({ result: "Fail", message: "Contact Name Must be Unique" });
    else if (error.errors.name)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.name.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.delete("/contact/:_id", verifyToken, async (req, res) => {
  try {
    var data = await Contact.findOne({ _id: req.params._id });
    if (data) {
      await data.delete();
      res.send({ result: "Done", message: "Record is Deleted!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
//API for newslatter
app.post("/newslatter", async (req, res) => {
  try {
    var data = new Newslatter(req.body);
    await data.save();
    res.send({
      result: "Done",
      message:
        "Thanks to Subscribe our Newslatter Service!!!! Now We Will Send an Email About Our Latest Products and Offerse!!!",
    });
  } catch (error) {
    if (error.keyValue)
      res.status(401).send({
        result: "Fail",
        message: "Your Email Id is Already Registered With US",
      });
    else if (error.errors.email)
      res
        .status(401)
        .send({ result: "Fail", message: error.errors.email.message });
    else
      res
        .status(500)
        .send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.get("/newslatter", verifyToken, async (req, res) => {
  try {
    var data = await Newslatter.find();
    res.send({ result: "Done", data: data });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.delete("/newslatter/:_id", verifyToken, async (req, res) => {
  try {
    var data = await Newslatter.findOne({ _id: req.params._id });
    if (data) {
      await data.delete();
      res.send({ result: "Done", message: "Record is Deleted!!!!!" });
    } else res.status(404).send({ result: "Fail", message: "Invalid ID" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});

//API to Search
app.post("/search", async (req, res) => {
  try {
    var data = await Product.find({
      $or: [
        { name: { $regex: `${req.body.search}`, $options: "i" } },
        { maincategory: { $regex: `${req.body.search}`, $options: "i" } },
        { subcategory: { $regex: `${req.body.search}`, $options: "i" } },
        { brand: { $regex: `${req.body.search}`, $options: "i" } },
        { color: { $regex: `${req.body.search}`, $options: "i" } },
        { size: { $regex: `${req.body.search}`, $options: "i" } },
        { stock: { $regex: `${req.body.search}`, $options: "i" } },
        { description: { $regex: `${req.body.search}`, $options: "i" } },
      ],
    });
    res.send({ result: "Done", data: data });
  } catch (error) {
    console.log(error);
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});

//API for Password Reset
app.post("/reset-username", async (req, res) => {
  try {
    var data = await User.findOne({ username: req.body.username });
    if (data) {
      let otp = parseInt(Math.random() * 1000000);
      data.otp = otp;
      await data.save();
      mailOption = {
        from: from,
        to: data.email,
        subject: "OTP for Password Reset !!! : Team Ecom",
        text: `
                            OTP for Password Reset is ${otp}
                            Team : LiveShop PVT LTD
                            Noida
                        `,
      };
      transporter.sendMail(mailOption, (error, data) => {
        if (error) console.log(error);
      });
      res.send({
        result: "Done",
        message: "OTP is Sent on Your Registered Email Id!!",
      });
    } else
      res.status(404).send({ result: "Fail", message: "Invalid Username!!" });
  } catch (error) {
    res
      .status(500)
      .send({ result: "Fail", message: "Internal Server Error!!" });
  }
});
app.post("/reset-otp", async (req, res) => {
  try {
    var data = await User.findOne({ username: req.body.username });
    if (data) {
      if (data.otp == req.body.otp) res.send({ result: "Done" });
      else res.status(401).send({ result: "Fail", message: "Invalid OTP!!!" });
    } else res.status(401).send({ result: "Fail", message: "UnAuthorized!!!" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
app.post("/reset-password", async (req, res) => {
  try {
    var data = await User.findOne({ username: req.body.username });
    if (data) {
      bcrypt.hash(req.body.password, 12, async (error, hash) => {
        if (error)
          res
            .status(500)
            .send({ result: "Fail", message: "Internal Server Error" });
        else {
          data.password = hash;
          await data.save();
          res.send({ result: "Done", message: "Password Has Been Reset!!!!!" });
        }
      });
    } else res.status(401).send({ result: "Fail", message: "UnAuthorized!!!" });
  } catch (error) {
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});
// app.use('*', express.static(path.join(__dirname, 'build')));
var port = 8000;
app.listen(port, () => console.log(`Server is Running at PORT ${port}`));
