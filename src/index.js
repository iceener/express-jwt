import dotenv from 'dotenv'
import jwt from 'jsonwebtoken'
import express from 'express'
import cookieParser from 'cookie-parser'

dotenv.config()

const app = express()

app.use(express.json())
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }))

app.get('/api/users', authenticate, (req, res) => {
	const users = [{ id: 1, name: 'Adam' }]

	res.send(users)
})

app.post('/api/auth/login', (req, res) => {
	const email = req.body.email
	const password = req.body.password

	// const validPassword = await bcrypt.compare(password, user[0].password)

	const accessToken = generateAccessToken({ id: 1 })
	const refreshToken = jwt.sign({ id: 1 }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: 525600 })
	// Save refresh Token in DB

	res.cookie('JWT', accessToken, {
		maxAge: 86400000,
		httpOnly: true,
	})

	res.send({ accessToken, refreshToken })
})

app.post('/api/auth/refresh', (req, res) => {
	const refreshToken = req.body.token

	if (!refreshToken) {
		return res.status(401)
	}

	// TODO: Check if refreshToken exists in DB

	const validToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET)

	if (!validToken) {
		return res.status(403)
	}

	const accessToken = generateAccessToken({ id: 1 })

	res.send({ accessToken })
})

function generateAccessToken(payload) {
	return jwt.sign(payload, process.env.TOKEN_SECRET, { expiresIn: 86400 }) // 86400
}

function authenticate(req, res, next) {
	// const authHeader = req.headers['authorization']
	// const token = authHeader && authHeader.split(' ')[1]
	const token = req.cookies.JWT

	if (token === null) return res.sendStatus(401)

	jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
		if (err) return res.sendStatus(403)

		req.user = user
		next()
	})
}

app.listen(3000, () => {
	console.log('Server is up!')
})
