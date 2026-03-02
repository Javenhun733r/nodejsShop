const path = require('path');
const fs = require('fs');
const https = require('https');
const MongoStore = require('connect-mongo').default;
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const multer = require('multer');
const session = require('express-session');
const csrf = require('csurf');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const flash = require('connect-flash');
const errorController = require('./controllers/error');
const User = require('./models/user');

const MONGODB_URI = process.env.DB_URL;

const app = express();
const store = MongoStore.create({
	mongoUrl: MONGODB_URI,
	collectionName: 'sessions',
});
const csrfProtection = csrf();
const privateKey = fs.readFileSync('server.key');
const certificate = fs.readFileSync('server.cert');
const fileStorage = multer.diskStorage({
	destination: (req, file, cb) => {
		cb(null, 'images');
	},
	filename: (req, file, cb) => {
		cb(
			null,
			new Date().toISOString().replace(/:/g, '-') + '-' + file.originalname,
		);
	},
});
app.set('view engine', 'ejs');
app.set('views', 'views');

const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');
const authRoutes = require('./routes/auth');
const accessLogStream = fs.createWriteStream(
	path.join(__dirname, 'access.log'),
	{ flags: 'a' },
);
app.use(helmet());
app.use(compression());
app.use(morgan('combined', { stream: accessLogStream }));
const fileFilter = (req, file, cb) => {
	if (
		file.mimetype === 'image/png' ||
		file.mimetype === 'image/jpg' ||
		file.mimetype === 'image/jpeg'
	) {
		cb(null, true);
	} else {
		cb(null, false);
	}
};
app.use(bodyParser.urlencoded({ extended: false }));
app.use(
	multer({ storage: fileStorage, fileFilter: fileFilter }).single('image'),
);
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use(
	session({
		secret: 'my secret',
		resave: false,
		saveUninitialized: false,
		store: store,
	}),
);
app.use(csrfProtection);
app.use(flash());
app.use((req, res, next) => {
	res.locals.isAuthenticated = req.session ? req.session.isLoggedIn : false;
	res.locals.csrfToken = req.csrfToken();
	next();
});
app.use((req, res, next) => {
	if (!req.session.user) {
		return next();
	}
	User.findById(req.session.user._id)
		.then(user => {
			if (!user) {
				return next();
			}
			req.user = user;
			next();
		})
		.catch(err => {
			next(new Error(err));
		});
});

app.use('/admin', adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);
app.get('/500', errorController.get500);
app.use(errorController.get404);
app.use((error, req, res, next) => {
	const isAuth = req.session ? req.session.isLoggedIn : false;
	res.status(500).render('500', {
		pageTitle: 'Error!',
		path: '/500',
		isAuthenticated: isAuth,
	});
});
mongoose
	.connect(MONGODB_URI)
	.then(result => {
		// https
		// 	.createServer({ key: privateKey, cert: certificate }, app)
		// 	.listen(process.env.PORT || 3000);
		app.listen(process.env.PORT || 3000);
	})
	.catch(err => {
		console.log(err);
	});
