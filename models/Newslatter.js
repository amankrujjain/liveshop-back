const mongoose = require("mongoose")

const NewslatterSchema = new mongoose.Schema({
    email:{
        type:String,
        unique:true,
        required:[true,"Email Address Must Required to Subscribe Our Newslatter Service"]
    }
})
const Newslatter = new mongoose.model("Newslatter",NewslatterSchema)
module.exports = Newslatter