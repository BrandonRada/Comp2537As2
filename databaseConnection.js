require('dotenv').config();

const mongodb_host = "cluster0.vsnudks.mongodb.net";
const mongodb_user = "user1";
const mongodb_password = "Strongholdminer12";

const MongoClient = require("mongodb").MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true`;
var database = new MongoClient(atlasURI, {useNewUrlParser: true, useUnifiedTopology: true});
module.exports = {database};