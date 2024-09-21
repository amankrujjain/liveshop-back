const mongoose = require("mongoose")

const WishlistSchema = new mongoose.Schema({
    userid:{
        type:String,
        required:[true,"User Id Must Required"]
    },
    productid:{
        type:String,
        required:[true,"Product Id Must Required"]
    },
    name:{
        type:String,
        required:[true,"Product Name Must Required"]
    },
    maincategory:{
        type:String,
        required:[true,"Maincategory Name Must Required"]
    },
    subcategory:{
        type:String,
        required:[true,"Subcategory Name Must Required"]
    },
    brand:{
        type:String,
        required:[true,"Brand Name Must Required"]
    },
    color:{
        type:String,
        required:[true,"Color Must Required"]
    },
    size:{
        type:String,
        required:[true,"Size Must Required"]
    },
    price:{
        type:Number,
        required:[true,"Price Must Required"]
    },
    pic:{
        type:String,
        default:""
    }
})
const Wishlist = new mongoose.model("Wishlist",WishlistSchema)
module.exports = Wishlist