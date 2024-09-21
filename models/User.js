const mongoose = require("mongoose");

const WebAuthnCredentialSchema = new mongoose.Schema({
    credentialId:{
        type: String,
        required: true,
    },
    publicKey:{
        type:String,
        required: true,
    },
    signCount:{
        type: String,
        required: true,
        default: 0,
    },
    deviceName:{
        type: String,
        default: ''
    },
    added_at:{
        type: Date,
        default: Date.now,
    },
});

const UserSchema = new mongoose.Schema({
    name:{
        type:String,
        required:[true,"User Name Must Required"]
    },
    username:{
        type:String,
        unique:true,
        required:[true,"User Name Must Required"]
    },
    email:{
        type:String,
        required:[true,"User Email Address Must Required"]
    }, 
    phone:{
        type:String,
        required:[true,"User Phone Number Must Required"]
    },
    password:{
        type:String,
        required:[true,"User Password Number Must Required"]
    },
    addressline1:{
        type:String,
        default:""
    },
    addressline2:{
        type:String,
        default:""
    },
    addressline3:{
        type:String,
        default:""
    },
    pin:{
        type:String,
        default:""
    },
    city:{
        type:String,
        default:""
    },
    state:{
        type:String,
        default:""
    },
    pic:{
        type:String,
        default:""
    },
    role:{
        type:String,
        default:"User"
    },
    otp:{
        type:String,
        default:""
    },
    tokens:[String],
    webAuthnCredentials: [WebAuthnCredentialSchema],
    webauthnChallenge:{
        type: String,
        default:''
    },
});
const User = new mongoose.model("User",UserSchema)
module.exports = User