const mongoose = require('mongoose');
require('dotenv').config();

mongoose.connect(process.env.MONGODB_URI, {useNewUrlParser: true, useUnifiedTopology: true
    }).then(() => {
        console.log("Base de datos connectada");
    }).catch((err) => {
        console.log("Error de conneccion: ", err);
    });
module.exports = mongoose;