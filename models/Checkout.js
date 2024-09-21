const mongoose = require("mongoose")

const CheckoutSchema = new mongoose.Schema({
    userid:{
        type:String,
        required:[true,"User Id Must Required"]
    },
    paymentmode:{
        type:String,
        default:"COD"
    },
    paymentstatus:{
        type:String,
        default:"Pending"
    },
    orderstatus:{
        type:String,
        default:"Order Placed"
    },
    rppid:{
        type:String,
        default:""
    },
    date:{
        type:String,
        default:""
    },
    totalamount:{
        type:Number,
        required:[true,"Checkout Total Amount Must Required"]
    },
    shippingamount:{
        type:Number,
        required:[true,"Checkout Shipping Amount Must Required"]
    },
    finalamount:{
        type:Number,
        required:[true,"Checkout Final Amount Must Required"]
    },
    products:[
        {
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
            qty:{
                type:Number,
                default:1
            },
            total:{
                type:Number,
                required:[true,"Total Must Required"]
            },
            pic:{
                type:String,
                default:""
            }
        }
    ]
})
const Checkout = new mongoose.model("Checkout",CheckoutSchema)
module.exports = Checkout