import express from "express";
import dotenv from 'dotenv';
import mongoose from 'mongoose';
// import authRoute from './api/routes/auth.js'
// import usersRoute from './api/routes/users.js'
// import hotelsRoute from './api/routes/hotels.js'
// import roomsRoute from './api/routes/rooms.js'
import cookieParser from "cookie-parser";
import cors from 'cors';
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken";
import Hotel from './models/Hotel.js';
import Room from "./models/Room.js";


const app = express();
dotenv.config();


// FUNCTIONS

// ERROR
const createError = (status, message) => {
    const err = new Error();
    err.status = status;
    err.message = message;
    return err;
};

// JWT

const verifyToken = (req, res, next) => {
    const token = req.cookies.access_token;
    if (!token) {
        return next(createError(401, "You are not allowed"))
    }
    jwt.verify(token, process.env.JWT, (err, user) => {
        if (err) return next(createError(403, "Invalid Token"));
        req.user = user;
        next()
    })
}

const verifyUser = (req, res, next) => {
    verifyToken(req, res, next, () => {
        if (req.user.id === req.params.id || req.user.isAdmin) {
            next()
        } else {
            return next(createError(403, "You are not authorized"));
        }
    })
}

const verifyAdmin = (req, res, next) => {
    verifyToken(req, res, next, () => {
        if (req.user.isAdmin) {
            next()
        } else {
            return next(createError(403, "You are not authorized"));
        }
    })
}

// MONGO CONNECTION

const connect = async () => {
    try {
        await mongoose.connect(`mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.j2m70h0.mongodb.net/booking?retryWrites=true&w=majority`);
        console.log("Connected to MongoDB")
    } catch (error) {
        handleError(error);
    }
}

mongoose.connection.on("disconnected", () => {
    console.log("MongoDB disconnected")
})
mongoose.connection.on("connected", () => {
    console.log("MongoDB connected")
})

app.get('/', (req, res) => {
    res.send('Hello, Hotel booking server new')
})
app.get('/hotel', (req, res) => {
    res.send('hi, Hotel booking server')
})


// middle wares
app.use(cors())
app.use(cookieParser())
app.use(express.json())


// AUTH

app.post('/register', async (req, res, next) => {
    try {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.password, salt);
        const newUser = new User({
            username: req.body.username,
            email: req.body.email,
            password: hash,
        })

        await newUser.save()
        res.status(200).send("New user created")
    } catch (err) {
        next(err)
    }
})

app.post('/login', async (req, res, next) => {
    try {
        const user = await User.findOne({ username: req.body.username })
        if (!user) return next(createError(404, "User not found"))
        const isPasswordCorrect = await bcrypt.compare(req.body.password, user.password)
        if (!isPasswordCorrect) return next(createError(400, "Wrong password"))

        const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.JWT)
        const { password, isAdmin, ...otherDetails } = user._doc;
        res.cookie("access_token", token, {
            httpOnly: true,
        })
            .status(200)
            .send({ details: { ...otherDetails }, isAdmin })
    } catch (err) {
        next(err)
    }
})


// HOTELS API



app.post('/hotels', async (req, res, next) => {
    const newHotel = new Hotel(req.body)
    try {
        const savedHotel = await newHotel.save();
        res.status(200).json(savedHotel);
    }
    catch (err) {
        next(err);
    }
})

app.put('/hotels/:id', async (req, res, next) => {
    try {
        const updatedHotel = await Hotel.findByIdAndUpdate(
            req.params.id,
            { $set: req.body },
            { new: true }
        )
        res.status(200).json(updatedHotel);
    }
    catch (err) {
        res.status(500).json(err);
    }
})

app.delete('/hotels/:id', async (req, res, next) => {
    try {
        await Hotel.findByIdAndDelete(
            req.params.id
        )
        res.status(200).json("Hotel Deleted Successfully");
    }
    catch (err) {
        res.status(500).json(err);
    }
})


app.get('/hotels/find/:id', async (req, res, next) => {
    try {
        const hotel = await Hotel.findById(
            req.params.id
        )
        res.status(200).json(hotel);
    }
    catch (err) {
        res.status(500).json(err);
    }
})


app.get('/hotels', async (req, res, next) => {
    const { min, max, ...others } = req.query;
    try {
        const hotels = await Hotel.find({ ...others, cheapestPrice: { $gt: min || 1, $lt: max || 999 }, }).limit(req.query.limit);
        res.status(200).json(hotels);
    }
    catch (err) {
        next(err);
    }
})


app.get('/hotels/countByCity', async (req, res, next) => {
    const cities = req.query.cities.split(",")
    try {
        const list = await Promise.all(cities.map(city => {
            return Hotel.countDocuments({ city: city })
        }))
        res.status(200).json(list);
    }
    catch (err) {
        next(err);
    }
})


app.get('/hotels/countByType', async (req, res, next) => {
    try {
        const hotelCount = await Hotel.countDocuments({ type: "Hotel" });
        const apartmentCount = await Hotel.countDocuments({ type: "apartment" });
        const resortCount = await Hotel.countDocuments({ type: "resort" });
        const cabinCount = await Hotel.countDocuments({ type: "cabin" });
        const campingCount = await Hotel.countDocuments({ type: "camping" });

        res.status(200).json([
            { type: "Hotel", count: hotelCount },
            { type: "apartments", count: apartmentCount },
            { type: "resorts", count: resortCount },
            { type: "cabins", count: cabinCount },
            { type: "camping", count: campingCount },
        ]);
    }
    catch (err) {
        next(err);
    }
})

app.get('/hotels/room/:id', async (req, res, next) => {
    try {
        const hotel = await Hotel.findById(req.params.id);
        const list = await Promise.all(
            hotel.rooms.map(room => {
                return Room.findById(room);
            })
        );
        res.status(200).json(list)
    } catch (err) {
        next(err);
    }
});




app.listen(8800, () => {
    connect()
    console.log("Server running")
})