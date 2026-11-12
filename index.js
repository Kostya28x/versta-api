import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import bcrypt from 'bcrypt'
import { randomUUID } from 'crypto'
import db from './db.js' // Подключаем нашу базу
import dotenv from 'dotenv'

dotenv.config()

const app = express()
const PORT = process.env.PORT || 4000

app.use(cors({
  origin: 'http://localhost:5173', // Точный адрес твоего сайта
  credentials: true // Разрешаем передачу куки
}))

app.use(express.json())
app.use(cookieParser())

// 1. Проверка работы
app.get('/api/v1/health', (req, res) => {
  res.json({ status: 'ok', message: 'Сервер Версты работает!' })
})

// 2. Регистрация
app.post('/api/v1/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body

    // Проверяем, есть ли уже такой пользователь
    const existingUser = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь с таким email уже существует' })
    }

    // Хешируем пароль (шифруем)
    const passwordHash = await bcrypt.hash(password, 10)

    // Сохраняем в базу
    const result = db.prepare(
      'INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)'
    ).run(email, passwordHash, name)

    // Создаем сессию (токен)
    const sessionId = randomUUID()
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 дней
    db.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').run(
      sessionId, result.lastInsertRowid, expiresAt.toISOString()
    )

    // Ставим куку
   res.cookie('sessionId', sessionId, {
  httpOnly: true,
  secure: false,          // <--- ДОЛЖНО БЫТЬ false для localhost
  sameSite: 'lax',        // <--- ДОЛЖНО БЫТЬ 'lax'
  maxAge: 7 * 24 * 60 * 60 * 1000
})
    res.json({ message: 'Регистрация успешна', user: { id: result.lastInsertRowid, name, email } })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Ошибка сервера при регистрации' })
  }
})

// 3. Вход
app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
    if (!user) {
      return res.status(400).json({ error: 'Неверный email или пароль' })
    }

    const isValid = await bcrypt.compare(password, user.password_hash)
    if (!isValid) {
      return res.status(400).json({ error: 'Неверный email или пароль' })
    }

    const sessionId = randomUUID()
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    db.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').run(
      sessionId, user.id, expiresAt.toISOString()
    )

    res.cookie('sessionId', sessionId, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 })
    res.json({ message: 'Вход выполнен', user: { id: user.id, name: user.name, email: user.email, role: user.role } })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Ошибка сервера при входе' })
  }
})

// 4. Проверка: кто я сейчас?
app.get('/api/v1/me', (req, res) => {
  const sessionId = req.cookies.sessionId
  if (!sessionId) return res.status(401).json({ error: 'Не авторизован' })

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId)
  if (!session || new Date(session.expires_at) < new Date()) {
    return res.status(401).json({ error: 'Сессия истекла' })
  }

  const user = db.prepare('SELECT id, name, email, role, avatar FROM users WHERE id = ?').get(session.user_id)
  res.json({ user })
})

// 5. Выход
app.post('/api/v1/auth/logout', (req, res) => {
  const sessionId = req.cookies.sessionId
  if (sessionId) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId)
  }
  res.clearCookie('sessionId')
  res.json({ message: 'Выход выполнен' })
})


// Обновление аватарки
app.post('/api/v1/me/avatar', (req, res) => {
  const sessionId = req.cookies.sessionId
  if (!sessionId) return res.status(401).json({ error: 'Не авторизован' })

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId)
  if (!session || new Date(session.expires_at) < new Date()) {
    return res.status(401).json({ error: 'Сессия истекла' })
  }

  const { avatar } = req.body // Получаем картинку в формате Base64

  try {
    db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(avatar, session.user_id)
    res.json({ message: 'Аватарка обновлена' })
  } catch (error) {
    res.status(500).json({ error: 'Ошибка при сохранении' })
  }
})

// Получить список избранных маршрутов пользователя
app.get('/api/v1/me/favorites', (req, res) => {
  const sessionId = req.cookies.sessionId
  if (!sessionId) return res.status(401).json({ error: 'Не авторизован' })

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId)
  if (!session || new Date(session.expires_at) < new Date()) {
    return res.status(401).json({ error: 'Сессия истекла' })
  }

  const favorites = db.prepare('SELECT route_id FROM favorites WHERE user_id = ?').all(session.user_id)
  res.json({ favorites: favorites.map(f => f.route_id) })
})

// Добавить в избранное
app.post('/api/v1/me/favorites', (req, res) => {
  const sessionId = req.cookies.sessionId
  if (!sessionId) return res.status(401).json({ error: 'Не авторизован' })

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId)
  if (!session) return res.status(401).json({ error: 'Сессия истекла' })

  const { routeId } = req.body

  try {
    db.prepare('INSERT OR IGNORE INTO favorites (user_id, route_id) VALUES (?, ?)').run(session.user_id, routeId)
    res.json({ message: 'Добавлено в избранное' })
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' })
  }
})

// Удалить из избранного
app.delete('/api/v1/me/favorites', (req, res) => {
  const sessionId = req.cookies.sessionId
  if (!sessionId) return res.status(401).json({ error: 'Не авторизован' })

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId)
  if (!session) return res.status(401).json({ error: 'Сессия истекла' })

  const { routeId } = req.body

  try {
    db.prepare('DELETE FROM favorites WHERE user_id = ? AND route_id = ?').run(session.user_id, routeId)
    res.json({ message: 'Удалено из избранного' })
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' })
  }
})

// Обновление имени (ника)
app.patch('/api/v1/me/name', (req, res) => {
  const sessionId = req.cookies.sessionId
  if (!sessionId) return res.status(401).json({ error: 'Не авторизован' })

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId)
  if (!session || new Date(session.expires_at) < new Date()) {
    return res.status(401).json({ error: 'Сессия истекла' })
  }

  const { name } = req.body
  if (!name || name.trim().length < 2) return res.status(400).json({ error: 'Имя слишком короткое' })

  try {
    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, session.user_id)
    res.json({ message: 'Имя обновлено', name })
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' })
  }
})

// Обновление пароля
app.patch('/api/v1/me/password', async (req, res) => {
  const sessionId = req.cookies.sessionId
  if (!sessionId) return res.status(401).json({ error: 'Не авторизован' })

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId)
  if (!session || new Date(session.expires_at) < new Date()) {
    return res.status(401).json({ error: 'Сессия истекла' })
  }

  const { oldPassword, newPassword } = req.body
  if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Заполните все поля' })
  if (newPassword.length < 6) return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' })

  try {
    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(session.user_id)
    const isValid = await bcrypt.compare(oldPassword, user.password_hash)
    
    if (!isValid) return res.status(400).json({ error: 'Неверный старый пароль' })

    const newHash = await bcrypt.hash(newPassword, 10)
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, session.user_id)
    
    res.json({ message: 'Пароль обновлен' })
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' })
  }
})


// Получить отзывы для маршрута
app.get('/api/v1/routes/:routeId/reviews', (req, res) => {
  const { routeId } = req.params
  const sessionId = req.cookies.sessionId
  let currentUserId = null

  if (sessionId) {
    const session = db.prepare('SELECT user_id FROM sessions WHERE id = ?').get(sessionId)
    if (session) currentUserId = session.user_id
  }

  try {
    const reviews = db.prepare(`
      SELECT r.*, u.name as user_name, u.avatar as user_avatar, u.role as user_role,
      (SELECT COUNT(*) FROM review_likes WHERE review_id = r.id) as likes_count
      FROM reviews r
      JOIN users u ON r.user_id = u.id
      WHERE r.route_id = ?
      ORDER BY r.created_at DESC
    `).all(routeId)

    // Проверяем, лайкнул ли текущий пользователь каждый отзыв
    const reviewsWithLikes = reviews.map(rev => {
      let isLiked = false
      if (currentUserId) {
        const like = db.prepare('SELECT * FROM review_likes WHERE review_id = ? AND user_id = ?').get(rev.id, currentUserId)
        isLiked = !!like
      }
      return { ...rev, isLiked }
    })

        // Считаем средний рейтинг
    const ratingData = db.prepare('SELECT AVG(rating) as avg_rating, COUNT(*) as count FROM reviews WHERE route_id = ?').get(routeId)
    const avgRating = ratingData.avg_rating ? Number(ratingData.avg_rating).toFixed(1) : 0
    const reviewCount = ratingData.count

    res.json({ reviews: reviewsWithLikes, avgRating, reviewCount })

   
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' })
  }
})

// Добавить отзыв
app.post('/api/v1/routes/:routeId/reviews', (req, res) => {
  const { routeId } = req.params
  const sessionId = req.cookies.sessionId
  if (!sessionId) return res.status(401).json({ error: 'Войдите, чтобы оставить отзыв' })

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId)
  if (!session) return res.status(401).json({ error: 'Сессия истекла' })

  const { rating, text } = req.body
  if (!rating || !text) return res.status(400).json({ error: 'Заполните оценку и текст' })

  try {
    db.prepare('INSERT INTO reviews (route_id, user_id, rating, text) VALUES (?, ?, ?, ?)').run(routeId, session.user_id, rating, text)
    res.json({ message: 'Отзыв добавлен' })
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' })
  }
})

// Лайкнуть/убрать лайк
app.post('/api/v1/reviews/:reviewId/like', (req, res) => {
  const { reviewId } = req.params
  const sessionId = req.cookies.sessionId
  if (!sessionId) return res.status(401).json({ error: 'Войдите, чтобы лайкнуть' })

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId)
  if (!session) return res.status(401).json({ error: 'Сессия истекла' })

  try {
    const existingLike = db.prepare('SELECT * FROM review_likes WHERE review_id = ? AND user_id = ?').get(reviewId, session.user_id)
    
    if (existingLike) {
      db.prepare('DELETE FROM review_likes WHERE review_id = ? AND user_id = ?').run(reviewId, session.user_id)
      res.json({ message: 'Лайк убран', liked: false })
    } else {
      db.prepare('INSERT INTO review_likes (review_id, user_id) VALUES (?, ?)').run(reviewId, session.user_id)
      res.json({ message: 'Лайк поставлен', liked: true })
    }
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' })
  }
})


// Получить рейтинги для всех маршрутов
app.get('/api/v1/routes/ratings', (req, res) => {
  try {
    const ratings = db.prepare(`
      SELECT route_id, AVG(rating) as avg_rating, COUNT(*) as count 
      FROM reviews 
      GROUP BY route_id
    `).all()
    res.json({ ratings })
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' })
  }
})

// Получить мои отзывы
app.get('/api/v1/me/reviews', (req, res) => {
  const sessionId = req.cookies.sessionId
  if (!sessionId) return res.status(401).json({ error: 'Не авторизован' })

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId)
  if (!session || new Date(session.expires_at) < new Date()) {
    return res.status(401).json({ error: 'Сессия истекла' })
  }

  try {
    const myReviews = db.prepare(`
      SELECT r.*, (SELECT COUNT(*) FROM review_likes WHERE review_id = r.id) as likes_count
      FROM reviews r
      WHERE r.user_id = ?
      ORDER BY r.created_at DESC
    `).all(session.user_id)
    
    res.json({ reviews: myReviews })
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' })
  }
})



// ВРЕМЕННЫЙ РОУТ: Чтобы сделать себя админом (выполнить 1 раз)
// Удаление отзыва (только для админа)
// Удаление отзыва (только для админа)
app.delete('/api/v1/reviews/:reviewId', (req, res) => {
  const { reviewId } = req.params
  const sessionId = req.cookies.sessionId
  if (!sessionId) return res.status(401).json({ error: 'Не авторизован' })

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId)
  if (!session) return res.status(401).json({ error: 'Сессия истекла' })

  // Проверяем, админ ли это
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(session.user_id)
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'У вас нет прав на удаление' })
  }

  try {
    db.prepare('DELETE FROM reviews WHERE id = ?').run(reviewId)
    res.json({ message: 'Отзыв удален' })
  } catch (error) {
    console.error("Ошибка удаления:", error) // <-- Это покажет ошибку в терминале сервера!
    res.status(500).json({ error: 'Ошибка сервера' })
  }
})

app.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`)
})

// Получить избранное любого пользователя
app.get('/api/v1/users/:userId/favorites', (req, res) => {
  const { userId } = req.params
  try {
    const favorites = db.prepare('SELECT route_id FROM favorites WHERE user_id = ?').all(userId)
    res.json({ favorites: favorites.map(f => f.route_id) })
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' })
  }
})

// Получить отзывы любого пользователя
app.get('/api/v1/users/:userId/reviews', (req, res) => {
  const { userId } = req.params
  try {
    const myReviews = db.prepare(`
      SELECT r.*, (SELECT COUNT(*) FROM review_likes WHERE review_id = r.id) as likes_count
      FROM reviews r
      WHERE r.user_id = ?
      ORDER BY r.created_at DESC
    `).all(userId)
    
    res.json({ reviews: myReviews })
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' })
  }
})




// npm start
//Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass