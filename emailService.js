// emailService.js
const nodemailer = require('nodemailer');

// Create the transporter once, globally
const transporter = nodemailer.createTransport({
    host: 'sandbox.smtp.mailtrap.io',
    port: 587,
    auth: {
        user: process.env.MAILTRAP_USER, // Get credentials from .env file
        pass: process.env.MAILTRAP_PASS,
    },
});

// Function to send email and return a Promise
const sendEmail = (to, subject, text) => {
    const mailOptions = {
        from: 'no-reply@example.com', // Sender's email
        to,                           // Receiver's email
        subject,                      // Subject of the email
        html: text,                   // Body of the email
    };

    return new Promise((resolve, reject) => {
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                reject(error); // Reject the promise if there's an error
            } else {
                resolve(info); // Resolve the promise with the info if email is sent
            }
        });
    });
};

module.exports = {
    sendEmail
};
