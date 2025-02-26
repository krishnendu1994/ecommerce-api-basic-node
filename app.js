require('dotenv').config();
const connectDB = require('./db');
const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body , validationResult } = require('express-validator');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;;
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const { sendEmail } = require('./emailService'); // Import the sendEmail function
const User = require('./models/user'); // Import the User model
const redis = require('redis');
const Cart = require('./models/cart');
const Order = require('./models/order');
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key'; // JWT Secret (save it in .env in real projects)
connectDB();

app.use(express.json());

app.use((req,res,next) => {
    const timestamp = new Date().toISOString();
    const string_log= `[${timestamp}] ${req.method} request made to: ${req.url}\n`;
    fs.appendFile('log.txt',string_log,(err,res) => {
        if(err) throw err;
    });
    next();
});

app.use((err, req, res, next) => {
    //console.error(err.stack);  // Log error stack for debugging

    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Internal Server Error',
    });
    res.status(err.status || 429).json({
        success: false,
        message: err.message || 'API Limit\'s exceeded.',
    });
    res.status(err.status || 403).json({
        success: false,
        message: err.message || 'Authentication Error.',
    });
});

// Authenticate Function
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const decoded = jwt.verify(token, JWT_SECRET);

    // Fetch user from MongoDB
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(401).json({ error: 'User not found' });

    // Check if tokenVersion matches
    if (user.tokenVersion !== decoded.tokenVersion) {
      return res.status(401).json({ error: 'Token has been invalidated. Please log in again.' });
    }

    req.user = user; // Attach user object to request
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};
// Define rate limit policy
const limiter = rateLimit({
    windowMs: process.env.RATE_LIMIT || 1 * 60 * 60 * 1000, // 1 hour 
    max: process.env.MAX_LIMIT_NUMBER || 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again after 1 day'
});
app.use(limiter); // Apply rate limiter to all routes

// Configure multer for image uploads
const storage = multer.diskStorage({
	destination : function(req,file,cb){
		cb(null,process.env.UPLOAD_DIR || "uploads/");
	},
	filename : function(req,file,cb){
		cb(null, Date.now() + path.extname(file.originalname));
	}
});

const upload = multer({
    storage: storage,
    limits: { fileSize: process.env.FILE_SIZE_LIMIT || 100 * 1024 * 1024 }, // 100MB file size limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg'];
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error('Only JPG, JPEG, PNG files are allowed'));
        }
        cb(null, true);
    }
});


app.get('/',authenticate, (req, res) => {
    
    res.send('Welcome to Product\'s api');
});
// Send Mail
app.post('/api/send-mail', upload.none(), async (req, res, next) => {
    const { email, subject, content } = req.body;

    // Example usage with async/await
    try {
        const result = await sendEmail(email, subject, content); // Wait for the email to be sent
        res.json({ success: true, message: 'Email Sent', info: result });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'An error occurred while sending the email' });
    }
});

// Authentication process
// Login Route
app.post('/api/generate-token', [
  body('username').notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  // Find the user in MongoDB
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user && user.role === 'user') { 
    return res.status(401).json({ error: 'should be admin/api user to access API\'s' });
  }

  // Check password with bcrypt.compare
  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });


    // Increment the tokenVersion for the user
    user.tokenVersion++;

    // Generate JWT Token with tokenVersion
    const token = jwt.sign(
      { userId: user.id, role: user.role, tokenVersion: user.tokenVersion },
      JWT_SECRET, // Secret key
      { expiresIn: '1h' } // Expiry time
    );

    // Save the updated user with incremented tokenVersion
    user.save();

    res.json({ token });
  });
});


// POST - Register a new user
app.post('/api/register', [
  body('username').isString().withMessage('Username must be a string').notEmpty().withMessage('Username is required'),
  body('email').isEmail().withMessage('Invalid email address').notEmpty().withMessage('Email is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, email, password, role = null } = req.body || {};

  // Check if the username already exists
  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ error: 'Username already exists' });
  }
  const existingUseremail = await User.findOne({ email });
  if (existingUseremail) {
    return res.status(400).json({ error: 'email already exists' });
  }


  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 12);

  // Create the new user
  const newUser = new User({
    username,
    email,
     password: hashedPassword,
    ...(role != null && { role }) // Adds 'role' only if it's not null or undefined
});

  // Save the user to the database
  await newUser.save();
  if(role === 'api-user')
  {
    res.status(201).json({ message: 'API User registered successfully' });
  }else{
    res.status(201).json({ message: 'User registered successfully' });
  }
  
});

// End Authentication


// Product start
const Product = require('./models/product'); // Import the Product model

// Get all products

app.get('/api/products-list/:page?', authenticate, async (req, res, next) => {
  try {
    const page = parseInt(req.params.page) || 1;
    const limit = parseInt(req.query.limit) || process.env.PAGINATION_LIMIT || 2;
    const startIndex = (page - 1) * limit;

    // Add filters (e.g., by category)
    const filter = {};
    if (req.query.category) {
      filter.category = req.query.category;
    }

    // Add sorting (e.g., by price)
    const sort = {};
    if (req.query.sortBy === 'price') {
      sort.price = req.query.sortOrder === 'desc' ? -1 : 1;
    }

    const totalProducts = await Product.countDocuments(filter);
    const products = await Product.find(filter)
      .sort(sort)
      .skip(startIndex)
      .limit(limit);

    const paginationInfo = {
      currentPage: page,
      totalPages: Math.ceil(totalProducts / limit),
      totalItems: totalProducts,
      nextPage: page < Math.ceil(totalProducts / limit) ? page + 1 : null,
      prevPage: page > 1 ? page - 1 : null,
    };

    res.json({ pagination: paginationInfo, data: products });
  } catch (err) {
    next(err);
  }
});

// Get product by ID
app.get('/api/products/:id', authenticate, async (req, res, next) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return next(new Error('Product not found'));
    res.json(product);
  } catch (err) {
    next(err);
  }
});

// Add a new product
app.post('/api/products', upload.single('image'), authenticate, async (req, res, next) => {
  try {
    const { name, price, category, stockQuantity } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    const newProduct = new Product({
      name,
      price,
      category,
      stockQuantity: stockQuantity || 0,
      imageUrl,
    });

    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (err) {
    next(err);
  }
});

// Update an existing product
app.put('/api/products/:id', upload.single('image'), authenticate, async (req, res, next) => {
  try {
    const { name, price, category, stockQuantity } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    const updatedProduct = await Product.findByIdAndUpdate(
      req.params.id,
      { name, price, category, stockQuantity, imageUrl },
      { new: true }
    );

    if (!updatedProduct) return next(new Error('Product not found'));
    res.json(updatedProduct);
  } catch (err) {
    next(err);
  }
});

// Delete a product
app.delete('/api/products/:id', authenticate, async (req, res, next) => {
  try {
    const deletedProduct = await Product.findByIdAndDelete(req.params.id);
    if (!deletedProduct) return next(new Error('Product not found'));
    res.json({ success: `Product "${deletedProduct.name}" deleted successfully.` });
  } catch (err) {
    next(err);
  }
});

app.get('/api/search-products', authenticate, async (req, res) => {
  const { query } = req.query;
  const products = await Product.find({ $text: { $search: query } });
  res.json(products);
});
// Product End


// Cart Start
// Redis client setup
const redisClient = redis.createClient();
redisClient.connect().catch(console.error);

// Add item to cart
app.post('/api/cart/:userId', authenticate , async (req, res) => {
  const { userId } = req.params;
  const { productId, quantity, price } = req.body;
  const item = { productId, quantity, price };

  
  // Update Redis
  const cartKey = `cart:${userId}`;
  let cart = JSON.parse(await redisClient.get(cartKey)) || { items: [], total: 0 };

  // Add or update item
  const existingItem = cart.items.find((i) => i.productId === productId);
  if (existingItem) {
    existingItem.quantity += quantity;
  } else {
    cart.items.push(item);
  }

  // Recalculate total
  cart.total = cart.items.reduce((acc, item) => acc + item.quantity * item.price, 0);

  // Save back to Redis
  await redisClient.set(cartKey, JSON.stringify(cart));
  await redisClient.expire(cartKey, 3600); // 1-hour expiration

  res.json({ message: 'Item added to cart', cart });
});

// Get cart
app.get('/api/cart/:userId',authenticate , async (req, res) => {
  const { userId } = req.params;
  const cartKey = `cart:${userId}`;
  
  let cart = JSON.parse(await redisClient.get(cartKey));
  if (!cart) {
    // If not in Redis, load from DB
    const dbCart = await Cart.findOne({ userId });
    if (dbCart) {
      cart = { items: dbCart.items, total: dbCart.total };
      await redisClient.set(cartKey, JSON.stringify(cart));
    } else {
      cart = { items: [], total: 0 };
    }
  }

  res.json(cart);
});
// Remove item from cart
app.delete('/api/cart/:userId/:productId',authenticate, async (req, res) => {
  const { userId, productId } = req.params;
  const cartKey = `cart:${userId}`;

  // Fetch the cart from Redis
  let cart = JSON.parse(await redisClient.get(cartKey));
  if (!cart) {
    return res.status(404).json({ error: 'Cart not found' });
  }

  // Remove the item with the specified productId
  const filteredItems = cart.items.filter(item => item.productId !== productId);
  
  if (filteredItems.length === 0) {
    // Remove cart from Redis if empty
    await redisClient.del(cartKey);

    // Remove cart from database if applicable
    await Cart.deleteOne({ userId });

    return res.json({ message: 'Cart is now empty and has been removed' });
  }

  // Recalculate the total
  const total = filteredItems.reduce((acc, item) => acc + item.quantity * item.price, 0);
  
  // Update the cart
  cart.items = filteredItems;
  cart.total = total;

  // Save the updated cart back to Redis
  await redisClient.set(cartKey, JSON.stringify(cart));

  // Update the cart in the database
  await Cart.updateOne({ userId }, { $set: { items: filteredItems, total } });

  res.json({ message: 'Item removed from cart', cart });
});


// Sync Redis carts to MongoDB
async function syncCarts() {
  const keys = await redisClient.keys('cart:*');
  for (const key of keys) {
    const userId = key.split(':')[1];
    const cart = JSON.parse(await redisClient.get(key));

    // Upsert into MongoDB
    await Cart.findOneAndUpdate(
      { userId },
      { items: cart.items, total: cart.total },
      { upsert: true }
    );
    console.log(`Synced cart for user ${userId}`);
  }
}

// Run sync every 5 minutes
setInterval(syncCarts, 300000);

// Order //

// Place Order
app.post('/api/order/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  const cartKey = `cart:${userId}`;

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const cart = JSON.parse(await redisClient.get(cartKey));
    if (!cart || cart.items.length === 0) {
      throw new Error('Cart is empty');
    }

    // Deduct stock for each product
    for (const item of cart.items) {
      const product = await Product.findById(item.productId).session(session);
      if (!product) {
        throw new Error(`Product ${item.productId} not found`);
      }
      if (product.stockQuantity < item.quantity) {
        throw new Error(`Insufficient stock for product ${product.name}`);
      }
      product.stockQuantity -= item.quantity;
      await product.save();
    }

    // Create order
    const newOrder = new Order({
      userId,
      items: cart.items,
      total: cart.total,
    });
    await newOrder.save({ session });

    // Clear cart
    await redisClient.del(cartKey);
    await Cart.deleteOne({ userId }).session(session);

    await session.commitTransaction();
    session.endSession();

    res.status(201).json({ message: 'Order placed successfully', order: newOrder });
  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    next(err);
  }
});

// Get user orders
app.get('/api/orders/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  const orders = await Order.find({ userId }).sort({ createdAt: -1 });
  res.json(orders);
});

// Update order status
app.put('/api/orders/:orderId/status', authenticate, async (req, res) => {
  const { orderId } = req.params;
  const { status } = req.body;

  if (!['pending', 'completed', 'shipped' , 'cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  const updatedOrder = await Order.findByIdAndUpdate(orderId, { status }, { new: true });
  if (!updatedOrder) {
    return res.status(404).json({ error: 'Order not found' });
  }

  res.json(updatedOrder);
});

// end order

// Order sort/group

app.get('/api/revenue-by-product', authenticate, async (req, res, next) => {
  try {
    const revenueByCategory = await Order.aggregate([
      // Unwind the items array to process each item individually
      { $unwind: '$items' },
      // Group by category and calculate total revenue
      {
        $group: {
          _id: '$items.productId',
          totalRevenue: { $sum: { $multiply: ['$items.quantity', '$items.price'] } },
        },
      },
      // Sort by totalRevenue in descending order
      { $sort: { totalRevenue: -1 } },
    ]);

    res.json(revenueByCategory);
  } catch (err) {
    next(err);
  }
});

// end

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});