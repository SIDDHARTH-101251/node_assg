const express = require('express')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const path = require('path')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const dbPath = path.join(__dirname, 'twitterClone.db')

let db = null

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })

    app.listen(3000, () => {
      console.log('Server Started At: http://localhost:3000/')
    })
  } catch (e) {
    console.log(`Error : ${e.message}`)
    process.exit(1)
  }
}

initializeDBAndServer()

// API 1
app.post('/register/', async (request, response) => {
  const userDetails = request.body
  const {username, password, name, gender} = userDetails

  const checkUserQuery = `
    SELECT *
    FROM user
    WHERE username = ?`

  const hashedPassword = await bcrypt.hash(password, 10)

  const createUserQuery = `
    INSERT INTO 
    user(username, password, name, gender)
    VALUES(?,?,?,?);`

  try {
    const user = await db.get(checkUserQuery, [username])

    if (user !== undefined) {
      response.status(400).send('User already exists')
    } else if (password.length < 6) {
      response.status(400).send('Password is too short')
    } else {
      await db.run(createUserQuery, [username, hashedPassword, name, gender])
      response.status(200).send('User created successfully')
    }
  } catch (error) {
    console.error('Error:', error.message)
    response.status(500).send('Internal Server Error')
  }
})

// API 2
app.post('/login/', async (request, response) => {
  const credentials = request.body

  const {username, password} = credentials

  const checkUserPresentOrNotQuery = `
    SELECT *
    FROM user
    WHERE username = ?`

  try {
    const result = await db.get(checkUserPresentOrNotQuery, [username])

    if (result === undefined) {
      response.status(400).send('Invalid user')
    } else {
      const isPasswordMatched = await bcrypt.compare(password, result.password)
      if (!isPasswordMatched) {
        response.status(400).send('Invalid password')
      } else {
        const payload = {
          username: username,
        }
        const jwtToken = jwt.sign(payload, 'Oh! Master!')
        response.send({jwtToken})
      }
    }
  } catch (error) {
    console.error('Error:', error.message)
    response.status(500).send('Internal Server Error')
  }
})

// Authentication Middleware
function authenticateJwtToken(request, response, next) {
  const authHeader = request.headers['authorization']
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    response.status(401).send('Invalid JWT Token')
    return
  }
  const jwtToken = authHeader.split(' ')[1]
  jwt.verify(jwtToken, 'Oh! Master!', (error, payload) => {
    if (error) {
      response.status(401).send('Invalid JWT Token')
    } else {
      request.username = payload.username
      next()
    }
  })
}

//API 3
app.get(
  '/user/tweets/feed',
  authenticateJwtToken,
  async (request, response) => {
    const {username} = request

    try {
      const getUserIdQuery = `
        SELECT user_id
        FROM user
        WHERE username = ?`
      const {user_id} = await db.get(getUserIdQuery, [username])

      const getUserIdsQuery = `
        SELECT following_user_id
        FROM follower
        WHERE follower_user_id = ?`
      const userFollowings = await db.all(getUserIdsQuery, [user_id])

      let tweetList = []
      for (const {following_user_id} of userFollowings) {
        const getUserTweetsQuery = `
          SELECT 
            username,
            tweet,
            date_time AS dateTime
          FROM tweet
          INNER JOIN user ON tweet.user_id = user.user_id
          WHERE user.user_id = ?
          ORDER BY dateTime DESC
          LIMIT 4`
        const userTweets = await db.all(getUserTweetsQuery, [following_user_id])
        tweetList = tweetList.concat(userTweets)
      }

      response.send(tweetList)
    } catch (error) {
      console.error('Error:', error.message)
      response.status(500).send('Internal Server Error')
    }
  },
)

//API 4
app.get('/user/following/', authenticateJwtToken, async (request, response) => {
  const {username} = request
  console.log(username)

  try {
    //get user id query
    const getUserIDQuery = `
    SELECT
      user_id
    FROM
      user
    WHERE
      username = "${username}";`
    const userId = await db.get(getUserIDQuery)
    console.log(userId)

    //get userIds of all people whome the user follows
    const getUserIDsQuery = `
    SELECT
      following_user_id
    FROM
      follower
    WHERE
      follower_user_id = ?;`
    const userIds = await db.all(getUserIDsQuery, [userId.user_id])
    console.log(userIds)

    let nameList = []

    //query to get names of people whome the user follows
    for (let i of userIds) {
      const getNamesQuery = `
      SELECT
        name
      FROM 
        user 
      WHERE
        user_id = ${i.following_user_id};
      `
      const names = await db.all(getNamesQuery)
      nameList = nameList.concat(names)
      console.log(names)
    }
    response.send(nameList)
  } catch (error) {
    console.log('Error: ', error.message)
    response.status(500)
    response.send('Internal Server Error')
  }
})

//API 5
app.get('/user/followers', authenticateJwtToken, async (request, response) => {
  const {username} = request
  console.log(username)
  try {
    const getUserIdQuery = `
    SELECT
      user_id
    FROM
      user
    WHERE
      username = "${username}";`
    const userId = await db.get(getUserIdQuery)
    console.log(userId)

    const getUserIdsWhoFollowUserQuery = `
    SELECT
      follower_user_id
    FROM
      follower
    WHERE
      following_user_id = ${userId.user_id};`
    const followersIds = await db.all(getUserIdsWhoFollowUserQuery)
    console.log(followersIds)

    let nameList = []

    //query to get names of people who follows the user
    for (let i of followersIds) {
      const getNamesQuery = `
      SELECT
        name
      FROM 
        user 
      WHERE
        user_id = ${i.follower_user_id};
      `
      const names = await db.all(getNamesQuery)
      nameList = nameList.concat(names)
      console.log(names)
    }
    response.send(nameList)
  } catch (error) {
    console.log('Error : ', error.message)
    response.status(500)
    response.send('Internal Server Error')
  }
})

//API 6
app.get('/tweets/:tweetId', authenticateJwtToken, async (request, response) => {
  const {username} = request
  try {
    const getUserIdQuery = `
      SELECT user_id
      FROM user
      WHERE username = ?`
    const {user_id} = await db.get(getUserIdQuery, [username])

    const {tweetId} = request.params

    const getTweetUserId = `
      SELECT user_id
      FROM tweet
      WHERE tweet_id = ?`
    const {user_id: tweetUserId} = await db.get(getTweetUserId, [tweetId])

    const checkFollowingQuery = `
      SELECT 1
      FROM follower
      WHERE follower_user_id = ? AND following_user_id = ?`
    const isFollowing = await db.get(checkFollowingQuery, [
      user_id,
      tweetUserId,
    ])

    if (!isFollowing) {
      response.status(401).send('Unauthorized')
      return
    }

    const getTweetDataAndAnalytics = `
      SELECT
        tweet,
        COUNT(like_id) AS likes,
        COUNT(reply_id) AS replies,
        tweet.date_time AS dateTime
      FROM tweet
      LEFT JOIN like ON tweet.tweet_id = like.tweet_id
      LEFT JOIN reply ON tweet.tweet_id = reply.tweet_id
      WHERE tweet.tweet_id = ?
      GROUP BY tweet.tweet_id`
    const result = await db.all(getTweetDataAndAnalytics, [tweetId])

    if (result.length === 0) {
      response.status(404).send('Tweet not found')
      return
    }

    response.send(result)
  } catch (error) {
    console.error('Internal Server Error:', error.message)
    response.status(500).send(`Error: ${error.message}`)
  }
})

//API 7
app.get(
  '/tweets/:tweetId/likes',
  authenticateJwtToken,
  async (request, response) => {
    const {username} = request
    try {
      const getUserIdQuery = `
      SELECT user_id
      FROM user
      WHERE username = ?`
      const {user_id} = await db.get(getUserIdQuery, [username])

      const {tweetId} = request.params

      const getTweetUserId = `
      SELECT user_id
      FROM tweet
      WHERE tweet_id = ?`
      const {user_id: tweetUserId} = await db.get(getTweetUserId, [tweetId])

      const checkFollowingQuery = `
      SELECT 1
      FROM follower
      WHERE follower_user_id = ? AND following_user_id = ?`
      const isFollowing = await db.get(checkFollowingQuery, [
        user_id,
        tweetUserId,
      ])

      if (!isFollowing) {
        response.status(401).send('Invalid Request')
        return
      }

      //query to get user ids who liked the tweet
      const getUserIdWhoLikedTheTweet = `
    SELECT
      user_id
    FROM
      like
    WHERE
      tweet_id = ${tweetId};`

      const likeListUsers = await db.all(getUserIdWhoLikedTheTweet)
      console.log(likeListUsers)
      let userNameList = []
      for (let i of likeListUsers) {
        const getUserNamesQuery = `
      SELECT
        username
      FROM
        user
      WHERE
        user_id = ${i.user_id};`

        const username = await db.get(getUserNamesQuery)
        userNameList = userNameList.concat(username.username)
      }
      response.send({likes: userNameList})
    } catch (error) {
      console.log(`${error.message}`)
    }
  },
)

//API 8
app.get(
  '/tweets/:tweetId/replies',
  authenticateJwtToken,
  async (request, response) => {
    const {username} = request
    try {
      // Get the user ID of the requester
      const getUserIdQuery = `
        SELECT user_id
        FROM user
        WHERE username = ?`
      const {user_id} = await db.get(getUserIdQuery, [username])

      const {tweetId} = request.params

      // Check if the requester is following the author of the tweet
      const getTweetUserId = `
        SELECT user_id
        FROM tweet
        WHERE tweet_id = ?`
      const {user_id: tweetUserId} = await db.get(getTweetUserId, [tweetId])

      const checkFollowingQuery = `
        SELECT 1
        FROM follower
        WHERE follower_user_id = ? AND following_user_id = ?`
      const isFollowing = await db.get(checkFollowingQuery, [
        user_id,
        tweetUserId,
      ])

      if (!isFollowing) {
        response.status(401).send('Invalid Request')
        return
      }

      // Get all replies for the tweet
      const getUserReplies = `
        SELECT u.name, r.reply
        FROM user AS u
        LEFT JOIN reply AS r ON u.user_id = r.user_id
        WHERE r.tweet_id = ?`
      const repliesList = await db.all(getUserReplies, [tweetId])

      // Send the replies back as a response to the client
      response.json(repliesList)
    } catch (error) {
      console.log(error.message)
      response.status(500).send('Internal Server Error')
    }
  },
)

//API 9
app.get('/user/tweets/', authenticateJwtToken, async (request, response) => {
  const {username} = request
  try {
    const getUserIdQuery = `
      SELECT user_id
      FROM user
      WHERE username = ?`

    const {user_id} = await db.get(getUserIdQuery, [username])

    const getAllTweetsQuery = `
      SELECT
        t.tweet,
        COUNT(l.like_id) AS likes,
        COUNT(r.reply_id) AS replies,
        t.date_time AS dateTime
      FROM
        tweet AS t
      LEFT JOIN
        like AS l ON t.tweet_id = l.tweet_id
      LEFT JOIN
        reply AS r ON t.tweet_id = r.tweet_id
      WHERE
        t.user_id = ?
      GROUP BY
        t.tweet_id`

    const tweetList = await db.all(getAllTweetsQuery, [user_id])
    console.log(tweetList)
    response.send(tweetList)
  } catch (error) {
    console.log(error.message)
    response.status(500).send('Internal Server Error')
  }
})

//API 10
app.post('/user/tweets/', authenticateJwtToken, async (request, response) => {
  const {username} = request
  try {
    const getUserIdQuery = `
      SELECT
        user_id
      FROM
        user
      WHERE
        username = "${username}";`
    const userId = await db.get(getUserIdQuery)
    const updateTweetQuery = `
    INSERT INTO
      tweet(
        tweet
      )
      VALUES("${tweet.tweet}")
      WHERE
        user_id = ${userId};`

    await db.run(updateTweetQuery)
    response.send('Created a Tweet')
  } catch (error) {
    console.log(error.message)
  }
})

//API 11
app.delete(
  '/tweets/:tweetId/',
  authenticateJwtToken,
  async (request, response) => {
    const {username} = request
    const {tweetId} = request.params

    try {
      const getUserIdQuery = `
      SELECT user_id
      FROM user
      WHERE username = ?`
      const {user_id: userId} = await db.get(getUserIdQuery, [username])

      const getUserIdBasedOnTweetQuery = `
      SELECT user_id
      FROM tweet
      WHERE tweet_id = ?`
      const {user_id: tweetUserId} = await db.get(getUserIdBasedOnTweetQuery, [
        tweetId,
      ])

      if (userId !== tweetUserId) {
        response.status(401).send('Invalid Request')
        return
      } else {
        const deleteTweetQuery = `
        DELETE FROM tweet
        WHERE tweet_id = ?`

        await db.run(deleteTweetQuery, [tweetId])
        response.send('Tweet Removed')
      }
    } catch (error) {
      console.error('Error:', error.message)
      response.status(500).send('Internal Server Error')
    }
  },
)

module.exports = app
