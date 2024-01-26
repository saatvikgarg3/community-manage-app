const mongoose=require("mongoose");
const connect=mongoose.connect("mongodb://127.0.0.1:27017/Login");
connect.then(()=>{
    console.log("Database Connected Successfully");
})
.catch((e)=>{
    console.log(e,"Database cannot connect");
});

const RoleSchema=new mongoose.Schema({
    name:{
        type: String,
        required: true,
        minlength: 2,
    },
    createdAt: {
        type: Date,
        default: Date.now,
      },
    updatedAt: {
        type: Date,
        default: null,
      },
});

const LoginSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        minlength: 2,
    },
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
        minlength: 6,
    },
    created_at: {
        type: Date,
        default: Date.now,
    },
});

const CommunitySchema = new mongoose.Schema({
    name: {
      type: String,
      required: true,
      unique: true,
    },
    slug: {
      type: String,
      required: true,
      unique: true,
    },
    owner: {
      type: String,
      required: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: {
      type: Date,
      default: null,
    },
  });
const MemberSchema=new mongoose.Schema({
    communityid:{
        type:String,
        required:true,
    },
    userid:{
        type:String,
        ref:'Users',
        required:true,
    },
    roleid:{
        type:String,
        ref:'role',
        required:true,
    },
    createdAt:{
        type:Date,
        default:Date.now,
    }
});
const collection=new mongoose.model("Users",LoginSchema);
const Communitycollection = mongoose.model('community', CommunitySchema);
const Rolecollection = mongoose.model('role', RoleSchema);
const Membercollection=mongoose.model('Member',MemberSchema);

module.exports={
    collection,
    Communitycollection,
    Rolecollection,
    Membercollection
};