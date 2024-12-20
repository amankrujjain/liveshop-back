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
const WebSocket = require('ws');
const ObjectId = require('mongoose').Types.ObjectId;


require("dotenv").config();

const SessionModel = require('./models/SessionModel');
const MongoStore = require("connect-mongo");
const crypto = require("crypto");
const generateSecretKey = require('./helpers/generateSecretKey');
const authMiddleware = require('./helpers/authMiddleware');

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


const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (ws) => {
  console.log('New client connected');

  // Send a welcome message to the newly connected client
  ws.send('Welcome to the WebSocket server!');

  // Handle messages from the client
  ws.on('message', (message) => {
    console.log('Received:', message);
    // Broadcast the message to all connected clients
    wss.clients.forEach(client => {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  });

  ws.on('close', () => {
    console.log('Client disconnected');
  });

  // Handle any error
  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

console.log('WebSocket server is running on ws://localhost:8000');


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

const upload = multer({
  storage: storage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/avif'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true)
    } else {
      cb(new multer.MulterError('Invalid file type. Only JPEG, PNG, WEBP, AVIF flies are allowed'))
    }
  }
});

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
app.post("/create-maincategory", authMiddleware("Admin"), async (req, res) => {
  try {

    var data = new Maincategory(req.body);
    await data.save();
    res.send({ result: "Done", message: "Maincategory is Created!!!!!" });
  } catch (error) {
    console.log(error)
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
app.put("/maincategory/:_id", authMiddleware("Admin"), async (req, res) => {
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
app.delete("/delete-maincategory/:_id", authMiddleware("Admin"), async (req, res) => {
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
app.post("/create-subcategory", authMiddleware("Admin"), async (req, res) => {
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
app.put("/update-subcategory/:_id", authMiddleware("Admin"), async (req, res) => {
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
app.delete("/delete-subcategory/:_id", authMiddleware("Admin"), async (req, res) => {
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
app.post("/create-brand", authMiddleware("Admin"), async (req, res) => {
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
app.put("/update-brand/:_id", authMiddleware("Admin"), async (req, res) => {
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
app.delete("/delete-brand/:_id", authMiddleware("Admin"), async (req, res) => {
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
app.post(
  '/create-product',
  authMiddleware("Admin"),
  (req, res, next) => {
    // Handle the multer upload with fields and custom error handling
    upload.fields([
      { name: 'pic1', maxCount: 1 },
      { name: 'pic2', maxCount: 1 },
      { name: 'pic3', maxCount: 1 },
      { name: 'pic4', maxCount: 1 },
    ])(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        // Multer-specific errors
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({
            result: 'Fail',
            message: 'File size exceeds the 10MB limit.',
          });
        }
        return res.status(400).json({
          result: 'Fail',
          message: 'Invalid file type. Only JPEG, PNG, WEBP, and AVIF files are allowed.',
        });
      } else if (err) {
        // General errors
        console.error('File upload error:', err);
        return res.status(500).json({
          result: 'Fail',
          message: 'Internal server error during file upload.',
        });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      // Handle text data and file upload data
      const productData = req.body; // This will contain text fields like name, category, etc.
      const productImages = req.files; // This will contain files

      // Create a new Product instance with both text and file data
      const newProduct = new Product({
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
        pic1: productImages.pic1 ? productImages.pic1[0].filename : null,
        pic2: productImages.pic2 ? productImages.pic2[0].filename : null,
        pic3: productImages.pic3 ? productImages.pic3[0].filename : null,
        pic4: productImages.pic4 ? productImages.pic4[0].filename : null,
      });

      // Save the new product to the database
      await newProduct.save();

      return res.status(201).json({
        result: 'Done',
        message: 'Product created successfully!',
        data: newProduct,
      });
    } catch (error) {
      console.error("Error while creating the product:", error);
      return res.status(500).json({
        result: 'Fail',
        message: 'Failed to create product. Please check all input fields and try again.',
      });
    }
  }
);


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
  (req, res, next) => {
    upload.fields([
      { name: "pic1", maxCount: 1 },
      { name: "pic2", maxCount: 1 },
      { name: "pic3", maxCount: 1 },
      { name: "pic4", maxCount: 1 },
    ])(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        // Handle multer-specific errors
        if (err.code === "LIMIT_FILE_SIZE") {
          return res.status(400).json({
            result: "Fail",
            message: "File size exceeds the 10MB limit.",
          });
        }
        return res.status(400).json({
          result: "Fail",
          message: "Invalid file type. Only JPEG, PNG, WEBP, and AVIF files are allowed.",
        });
      } else if (err) {
        // General errors
        console.error("File upload error:", err);
        return res.status(500).json({
          result: "Fail",
          message: "Internal server error during file upload.",
        });
      }
      next();
    });
  },
  authMiddleware("Admin"),
  async (req, res) => {
    try {
      console.log("Request Body:", req.body);
      console.log("Request Files:", req.files);

      const data = await Product.findOne({ _id: req.params._id });
      if (data) {
        // Update fields if provided in req.body or req.files
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

        // Update images if provided in req.files
        if (req.files.pic1) {
          fs.unlink(`./public/uploads/${data.pic1}`, (err) => {
            if (err) console.error("Error deleting old pic1:", err);
          });
          data.pic1 = req.files.pic1[0].filename;
        }
        if (req.files.pic2) {
          fs.unlink(`./public/uploads/${data.pic2}`, (err) => {
            if (err) console.error("Error deleting old pic2:", err);
          });
          data.pic2 = req.files.pic2[0].filename;
        }
        if (req.files.pic3) {
          fs.unlink(`./public/uploads/${data.pic3}`, (err) => {
            if (err) console.error("Error deleting old pic3:", err);
          });
          data.pic3 = req.files.pic3[0].filename;
        }
        if (req.files.pic4) {
          fs.unlink(`./public/uploads/${data.pic4}`, (err) => {
            if (err) console.error("Error deleting old pic4:", err);
          });
          data.pic4 = req.files.pic4[0].filename;
        }

        await data.save();
        return res.json({ result: "Done", message: "Record is Updated!" });
      } else {
        return res.status(404).json({ result: "Fail", message: "Invalid ID" });
      }
    } catch (error) {
      console.error("Error updating product:", error);
      const message = error.errors
        ? error.errors[Object.keys(error.errors)[0]].message
        : "Internal Server Error";
      return res.status(500).json({ result: "Fail", message });
    }
  }
);

app.delete("/delete-product/:_id", authMiddleware("Admin"), async (req, res) => {
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
    console.log("Error while deleting the product", error)
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

app.delete("/user/:_id", authMiddleware("Admin"), async (req, res) => {
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
    const token = jwt.sign({ id: user._id, role: user.role }, secretKey, { expiresIn: '1h' });

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
    // Assuming userID is in the format produced by isoUint8Array.fromUTF8String(user._id.toString())
    const originalUserID = isoUint8Array.toUTF8String(userID);
    console.log("Original userID", originalUserID)

    const sessionData = {
      challenge: options.challenge,
      userID: originalUserID,  // base64URL-encoded user ID
      expires: Date.now() + 5 * 60 * 1000,  // 5 minutes expiry
    };

    const session = new SessionModel({ data: sessionData });

    try {
      await session.save();
      console.log("Session successfully stored in MongoDB with ID:", session._id);

      // Immediately attempt to retrieve the session
      const storedSession = await SessionModel.findById(session._id);
      console.log("Retrieved session from DB:", storedSession);

      if (!storedSession) {
        console.error("Session not found in DB after save.");
      }
    } catch (error) {
      console.error("Failed to save session to MongoDB:", error);
      return res.status(500).send({ result: "fail", message: "Session storage failed" });
    }
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

    const session = await SessionModel.findOne({ _id: sessionID });

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

      const { credentialID, credentialPublicKey, counter } = registrationInfo;

      if (!credentialID) {
        throw new Error("Missing credentialID in registrationInfo");
      }

      // Push new credentials to the user's WebAuthn credentials
      user.webAuthnCredentials.push({
        credentialId: registrationInfo.credentialID,
        publicKey: isoBase64URL.fromBuffer(registrationInfo.credentialPublicKey),
        signCount: registrationInfo.counter,
        deviceType: registrationInfo.credentialDeviceType,
        backedUp: registrationInfo.credentialBackedUp,
        transports: attestationResponse.transports || [],
      });

      await user.save();

      // Delete the session after successful registration
      await SessionModel.findByIdAndDelete(sessionID);

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
    const { username } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).send({ result: "Fail", message: "User not found" });
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

    // Generate WebAuthn options for authentication
    const options = await generateAuthenticationOptions({
      rpID: RPID,
      allowCredentials: user.webAuthnCredentials.map((cred) => ({
        id: cred.credentialId,
        type: "public-key",
        transports: ["internal"],
      })),
      userVerification: "preferred",
    });

    // Create a new session specific to this login attempt
    const sessionData = {
      challenge: options.challenge,
      userID: user._id,  // Keep as ObjectId without converting to a string
      expires: Date.now() + 5 * 60 * 1000,  // Expire in 5 minutes
    };

    const session = new SessionModel({ data: sessionData });
    await session.save();

    console.log("New session created for login with ID:", session._id);

    // Send the WebAuthn options and the new sessionID to the client
    return res.status(200).json({ options, sessionID: session._id });
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
    const { username, authResponse, sessionID } = req.body;

    // Find user in the database
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).send({ result: "Fail", message: "User not found" });
    }

    const session = await SessionModel.findById(sessionID);
    if (!session) {
      return res.status(400).send({ result: "fail", message: "Session is invalid or has expired." });
    }

    // Convert session.data.userID to ObjectId and compare with user._id
    if (!ObjectId(session.data.userID).equals(user._id)) {
      return res.status(400).send({ result: "fail", message: "Session does not match the user." });
    }


    // Check if session contains a valid challenge
    const expectedChallenge = session.data.challenge;
    if (!expectedChallenge) {
      return res.status(400).send({ result: "Fail", message: "Challenge missing or session expired" });
    }

    // Find user's WebAuthn credential
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
      : "localhost";

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

      // Delete the session after successful verification
      await SessionModel.findByIdAndDelete(sessionID);

      const secretKey = generateSecretKey(user.role);

      // Generate a JWT token upon successful login
      const token = jwt.sign({ id: user._id, role: user.role }, secretKey, { expiresIn: '1h' });

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
app.post("/logout", async (req, res) => {
  try {
    const { username, token } = req.body;

    // Ensure token and username are provided
    if (!token || !username) {
      return res.status(400).json({
        result: "Fail",
        message: "Token or username is missing",
      });
    }

    // Find the user by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ result: "Fail", message: "User not found" });
    }

    // Verify the token (assuming JWT)
    let decodedToken;
    try {
      decodedToken = jwt.verify(token, generateSecretKey(user.role));  // Validate token
    } catch (err) {
      return res.status(401).json({
        result: "Fail",
        message: "Invalid token",
      });
    }

    // Ensure the token matches the user
    if (decodedToken.id !== user._id.toString()) {
      return res.status(403).json({
        result: "Fail",
        message: "Token does not match the user",
      });
    }

    // Find and remove the token from the user's tokens array
    const tokenIndex = user.tokens.findIndex((item) => item === token);
    if (tokenIndex === -1) {
      return res.status(401).json({
        result: "Fail",
        message: "Token not found or already logged out",
      });
    }

    user.tokens.splice(tokenIndex, 1); // Remove token from the array
    await user.save();

    res.status(200).json({
      result: "Done",
      message: "You have logged out successfully",
    });
  } catch (error) {
    console.error("Logout Error:", error);
    res.status(500).json({ result: "Fail", message: "Internal Server Error" });
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

const mongoose = require("mongoose");

app.post(
  "/add-to-cart/user/:userId/product/:productId",
  authMiddleware(["Admin", "User"]),
  async (req, res) => {
    const { userId, productId } = req.params;
    const { quantity } = req.body;

    // Validate userId and productId
    if (!mongoose.Types.ObjectId.isValid(userId) || !mongoose.Types.ObjectId.isValid(productId)) {
      console.log("Validation failed: Invalid User ID or Product ID", { userId, productId });
      return res.status(400).send({
        result: "Fail",
        message: "Invalid User ID or Product ID",
      });
    }

    try {
      console.log("Cart data received:", { userId, productId, quantity });

      // Find existing cart for the user
      let cart = await Cart.findOne({ userId });
      console.log("Existing cart:", cart);

      if (cart) {
        // Check if the product already exists in the cart
        const productIndex = cart.products.findIndex(
          (item) => item.productId.toString() === productId
        );
        console.log("Product index in cart:", productIndex);

        if (productIndex >= 0) {
          // Increment quantity for the existing product
          const existingQuantity = cart.products[productIndex].quantity;
          console.log(
            `Updating quantity for product. Existing: ${existingQuantity}, Adding: ${quantity || 1}`
          );
          cart.products[productIndex].quantity += quantity || 1;
        } else {
          // Add the new product to the cart
          console.log("Adding new product to cart:", { productId, quantity: quantity || 1 });
          cart.products.push({ productId, quantity: quantity || 1 });
        }
      } else {
        // Create a new cart if none exists
        console.log("No existing cart found. Creating a new cart.");
        cart = new Cart({
          userId,
          products: [{ productId, quantity: quantity || 1 }],
        });
      }

      // Save the cart to the database
      console.log("Saving cart to database...");
      await cart.save();
      console.log("Cart saved successfully.");

      // Respond with success
      res.status(200).send({
        result: "Done",
        message: "Product added/updated in cart",
        cart,
      });
    } catch (error) {
      console.error("Error adding to cart:", error);

      // Respond with internal server error
      res.status(500).send({
        result: "Fail",
        message: "Internal Server Error",
      });
    }
  }
);


app.get("/cart-item/user/:userId", authMiddleware(["User", "Admin"]), async (req, res) => {
  try {
    const { userId } = req.params; // Fetch userId from request params
    const data = await Cart.findOne({ userId }).populate("products.productId"); // Populate product details
    
    if (data) {
      res.send({ result: "Done", data: data.products || [] }); // Return only products array
    } else {
      res.status(404).send({ result: "Fail", message: "No cart items found for this user" });
    }
  } catch (error) {
    console.error("Error fetching cart items:", error);
    res.status(500).send({ result: "Fail", message: "Internal Server Error" });
  }
});

app.put("/cartUser/:_id", verifyToken, async (req, res) => {
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
app.post("/checkout", authMiddleware("Admin"), async (req, res) => {
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
