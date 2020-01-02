const {Router} = require('express');
const bcript = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const {check, validationResult} = require('express-validator');
const Users = require('../models/User')
const router = Router();

// /api/auth/register
router.post(
  '/register',
  [
    check('email', 'Incorrect email').isEmail(),
    check('password', 'Minimum password length 6 characters')
      .isLength({ min: 6 })
  ],
  async (req, res) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Invalid credentials'
      })
    }
    
    const { email, password } = req.body;
    const candidate = await Users.findOne({ email });

    if(candidate) {
      return res.status(400).json({ message: "User already exist" })
    }

    const hachedPassword = await bcript.hash(password, 12);
    const user = new Users({  email, password: hachedPassword });

    await user.save();

    res.status(201).json({ message: 'User has been created' });

  } catch (e) {
    res.status(500).json({ message: 'Something wrong, try again' })
  }
});

// /api/auth/login
router.post(
  '/login',
  [
    check('email', 'Incorrect email').normalizeEmail().isEmail(),
    check('password', 'Incorrect password').exists()
  ],
  async (req, res) => {
    try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Login data incorrect'
      })
    }
    
    const { email, password } = req.body;
    const user = await Users.findOne({ email });
    
    if(!user) {
      return res.status(400).json({message: 'User is not found'});
    };

    const isMatch = await bcript.compare(password, user.password);

    if(!isMatch) {
      return res.status(400).json({message: 'Incorrect password, try again'});
    }

    const token = jwt.sign(
      { userId: user.id },
      config.get('jwtSecret'),
      { expiresIn: '1h' }
    )

    res.json({ token, userId: user.id })

  } catch (e) {
    res.status(500).json({ message: 'Something wrong, try again' })
  }
})

module.exports = router;