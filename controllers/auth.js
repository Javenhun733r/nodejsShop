const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { BrevoClient } = require('@getbrevo/brevo');
const User = require('../models/user');
const { validationResult } = require('express-validator');
const brevo = new BrevoClient({
	apiKey: process.env.BREVO_API,
});
exports.getLogin = (req, res, next) => {
	let message = req.flash('error');
	if (message.length > 0) {
		message = message[0];
	} else {
		message = null;
	}
	res.render('auth/login', {
		path: '/login',
		pageTitle: 'Login',
		errorMessage: message,
		oldInput: {
			email: '',
			password: '',
		},
		validationErrors: [],
	});
};

exports.getSignup = (req, res, next) => {
	let message = req.flash('error');
	if (message.length > 0) {
		message = message[0];
	} else {
		message = null;
	}
	res.render('auth/signup', {
		path: '/signup',
		pageTitle: 'Signup',
		errorMessage: message,
		oldInput: {
			email: '',
			password: '',
			confirmPassword: '',
		},
		validationErrors: [],
	});
};

exports.postLogin = (req, res, next) => {
	const email = req.body.email;
	const password = req.body.password;
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.status(422).render('auth/login', {
			path: '/login',
			pageTitle: 'Login',
			errorMessage: errors.array()[0].msg,
			oldInput: {
				email: email,
				password: password,
			},
			validationErrors: errors.array(),
		});
	}
	User.findOne({ email: email })
		.then(user => {
			if (!user) {
				return res.status(422).render('auth/login', {
					path: '/login',
					pageTitle: 'Login',
					errorMessage: 'Invalid email or password.',
					oldInput: {
						email: email,
						password: password,
					},
					validationErrors: [],
				});
			}
			bcrypt
				.compare(password, user.password)
				.then(doMatch => {
					if (doMatch) {
						req.session.isLoggedIn = true;
						req.session.user = user;
						return req.session.save(err => {
							console.log(err);
							res.redirect('/');
						});
					}
					return res.status(422).render('auth/login', {
						path: '/login',
						pageTitle: 'Login',
						errorMessage: 'Invalid email or password.',
						oldInput: {
							email: email,
							password: password,
						},
						validationErrors: [],
					});
				})
				.catch(err => {
					console.log(err);
					res.redirect('/login');
				});
		})
		.catch(err => {
			const error = new Error(err);
			error.httpStatusCode = 500;
			return next(error);
		});
};

exports.postSignup = (req, res, next) => {
	const email = req.body.email;
	const password = req.body.password;
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.status(422).render('auth/signup', {
			path: '/signup',
			pageTitle: 'Signup',
			errorMessage: errors.array()[0].msg,
			oldInput: {
				email: email,
				password: password,
				confirmPassword: req.body.confirmPassword,
			},
			validationErrors: errors.array(),
		});
	}

	bcrypt
		.hash(password, 12)
		.then(hashedPassword => {
			const user = new User({
				email: email,
				password: hashedPassword,
				cart: { items: [] },
			});
			return user.save();
		})
		.then(result => {
			res.redirect('/login');

			return brevo.transactionalEmails.sendTransacEmail({
				subject: 'Signup succeeded!',
				htmlContent: '<h1>You successfully signed up!</h1>',
				sender: { name: 'Shop Support', email: 'shopsupauth@hotmail.com' },
				to: [{ email: email }],
			});
		})
		.then(data => {
			console.log(
				'API called successfully. Returned data: ' + JSON.stringify(data),
			);
		})
		.catch(err => {
			const error = new Error(err);
			error.httpStatusCode = 500;
			return next(error);
		});
};
exports.postLogout = (req, res, next) => {
	req.session.destroy(err => {
		console.log(err);
		res.redirect('/');
	});
};
exports.getReset = (req, res, next) => {
	let message = req.flash('error');
	if (message.length > 0) {
		message = message[0];
	} else {
		message = null;
	}
	res.render('auth/reset', {
		path: '/reset',
		pageTitle: 'Reset Password',
		errorMessage: message,
	});
};
exports.postReset = (req, res, next) => {
	crypto.randomBytes(32, (err, buffer) => {
		if (err) {
			console.log(err);
			return res.redirect('/reset');
		}
		const token = buffer.toString('hex');
		const email = req.body.email;

		User.findOne({ email: email })
			.then(user => {
				if (!user) {
					req.flash('error', 'No account with that email found.');
					return res.redirect('/reset');
				}
				user.resetToken = token;
				user.resetTokenExpiration = Date.now() + 3600000;

				return user.save();
			})
			.then(result => {
				if (result) {
					res.redirect('/');
					return brevo.transactionalEmails.sendTransacEmail({
						subject: 'Password reset',
						htmlContent: `
              <p>You requested a password reset</p>
              <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password.</p>
            `,
						sender: { name: 'Shop Support', email: 'shopsupauth@hotmail.com' },
						to: [{ email: email }],
					});
				}
			})
			.then(data => {
				if (data) {
					console.log('Reset email sent successfully');
				}
			})
			.catch(err => {
				const error = new Error(err);
				error.httpStatusCode = 500;
				return next(error);
			});
	});
};
exports.getNewPassword = (req, res, next) => {
	const token = req.params.token;
	User.findOne({
		resetToken: token,
		resetTokenExpiration: { $gt: Date.now() },
	})
		.then(user => {
			let message = req.flash('error');
			if (message.length > 0) {
				message = message[0];
			} else {
				message = null;
			}
			res.render('auth/new-password', {
				path: '/new-password',
				pageTitle: 'New Password',
				errorMessage: message,
				userId: user._id.toString(),
				passwordToken: token,
			});
		})
		.catch(err => {
			const error = new Error(err);
			error.httpStatusCode = 500;
			return next(error);
		});
};
exports.postNewPassword = (req, res, next) => {
	const newPassword = req.body.password;
	const userId = req.body.userId;
	const passwordToken = req.body.passwordToken;
	let resetUser;
	User.findOne({
		resetToken: passwordToken,
		resetTokenExpiration: { $gt: Date.now() },
		_id: userId,
	})
		.then(user => {
			resetUser = user;
			return bcrypt.hash(newPassword, 12);
		})
		.then(hashedPassword => {
			resetUser.password = hashedPassword;
			resetUser.resetToken = null;
			resetUser.resetTokenExpiration = undefined;
			return resetUser.save();
		})
		.then(result => {
			res.redirect('/login');
		})
		.catch(err => {
			const error = new Error(err);
			error.httpStatusCode = 500;
			return next(error);
		});
};
