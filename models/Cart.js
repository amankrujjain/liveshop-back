const mongoose = require("mongoose");

const CartSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  products: [
    {
      productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Product",
        required: true
      },
      quantity: {
        type: Number,
        default: 1
      }
    }
  ],
  createdOn: {
    type: Date,
    default: Date.now()
  },
  isNotified: {
    type: Boolean,
    default: false
  }
});

const Cart = mongoose.model("Cart", CartSchema);
module.exports = Cart;
