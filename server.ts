/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import dataErasure from './routes/dataErasure'
import fs = require('fs')
import { Request, Response, NextFunction } from 'express'
import { sequelize } from './models'
import { UserModel } from './models/user'
import { QuantityModel } from './models/quantity'
import { CardModel } from './models/card'
import { PrivacyRequestModel } from './models/privacyRequests'
import { AddressModel } from './models/address'
import { SecurityAnswerModel } from './models/securityAnswer'
import { SecurityQuestionModel } from './models/securityQuestion'
import { RecycleModel } from './models/recycle'
import { ComplaintModel } from './models/complaint'
import { ChallengeModel } from './models/challenge'
import { BasketItemModel } from './models/basketitem'
import { FeedbackModel } from './models/feedback'
import { ProductModel } from './models/product'
import { WalletModel } from './models/wallet'
import logger from './lib/logger'
import config from 'config'
import path from 'path'
import morgan from 'morgan'
import colors from 'colors/safe'
import * as utils from './lib/utils'

const startTime = Date.now()
const finale = require('finale-rest')
const express = require('express')
const compression = require('compression')
const helmet = require('helmet')
const featurePolicy = require('feature-policy')
const errorhandler = require('errorhandler')
const cookieParser = require('cookie-parser')
const serveIndex = require('serve-index')
const bodyParser = require('body-parser')
const cors = require('cors')
const securityTxt = require('express-security.txt')
const robots = require('express-robots-txt')
const yaml = require('js-yaml')
const swaggerUi = require('swagger-ui-express')
const RateLimit = require('express-rate-limit')
const client = require('prom-client')
const ipfilter = require('express-ipfilter').IpFilter
const swaggerDocument = yaml.load(fs.readFileSync('./swagger.yml', 'utf8'))
const {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload
} = require('./routes/fileUpload')
const profileImageFileUpload = require('./routes/profileImageFileUpload')
const profileImageUrlUpload = require('./routes/profileImageUrlUpload')
const redirect = require('./routes/redirect')
const vulnCodeSnippet = require('./routes/vulnCodeSnippet')
const vulnCodeFixes = require('./routes/vulnCodeFixes')
const angular = require('./routes/angular')
const easterEgg = require('./routes/easterEgg')
const premiumReward = require('./routes/premiumReward')
const privacyPolicyProof = require('./routes/privacyPolicyProof')
const appVersion = require('./routes/appVersion')
const repeatNotification = require('./routes/repeatNotification')
const continueCode = require('./routes/continueCode')
const restoreProgress = require('./routes/restoreProgress')
const fileServer = require('./routes/fileServer')
const quarantineServer = require('./routes/quarantineServer')
const keyServer = require('./routes/keyServer')
const logFileServer = require('./routes/logfileServer')
const metrics = require('./routes/metrics')
const authenticatedUsers = require('./routes/authenticatedUsers')
const currentUser = require('./routes/currentUser')
const login = require('./routes/login')
const changePassword = require('./routes/changePassword')
const resetPassword = require('./routes/resetPassword')
const securityQuestion = require('./routes/securityQuestion')
const search = require('./routes/search')
const coupon = require('./routes/coupon')
const basket = require('./routes/basket')
const order = require('./routes/order')
const verify = require('./routes/verify')
const recycles = require('./routes/recycles')
const b2bOrder = require('./routes/b2bOrder')
const showProductReviews = require('./routes/showProductReviews')
const createProductReviews = require('./routes/createProductReviews')
const updateProductReviews = require('./routes/updateProductReviews')
const likeProductReviews = require('./routes/likeProductReviews')
const security = require('./lib/insecurity')
const datacreator = require('./data/datacreator')
const app = express()
const server = require('http').Server(app)
const appConfiguration = require('./routes/appConfiguration')
const captcha = require('./routes/captcha')
const trackOrder = require('./routes/trackOrder')
const countryMapping = require('./routes/countryMapping')
const basketItems = require('./routes/basketItems')
const saveLoginIp = require('./routes/saveLoginIp')
const userProfile = require('./routes/userProfile')
const updateUserProfile = require('./routes/updateUserProfile')
const videoHandler = require('./routes/videoHandler')
const twoFactorAuth = require('./routes/2fa')
const languageList = require('./routes/languages')
const imageCaptcha = require('./routes/imageCaptcha')
const dataExport = require('./routes/dataExport')
const address = require('./routes/address')
const payment = require('./routes/payment')
const wallet = require('./routes/wallet')
const orderHistory = require('./routes/orderHistory')
const delivery = require('./routes/delivery')
const deluxe = require('./routes/deluxe')
const memory = require('./routes/memory')
const chatbot = require('./routes/chatbot')
const locales = require('./data/static/locales.json')
const i18n = require('i18n')

const appName = config.get('application.customMetricsPrefix')
const startupGauge = new client.Gauge({
  name: `${appName}_startup_duration_seconds`,
  help: `Duration ${appName} required to perform a certain task during startup`,
  labelNames: ['task']
})

// Wraps the function and measures its (async) execution time
const collectDurationPromise = (name: string, func: Function) => {
  /**
   * An asynchronous function that starts a timer, executes a function, stops the timer, and returns the function's result.
   * @param {any[]}  args - The arguments to be passed onto the function `func`.
   * @returns {Promise} Returns the response of the executed function `func`.
   */
  return async (...args: any) => {
    const end = startupGauge.startTimer({ task: name })
    const res = await func(...args)
    end()
    return res
  }
}
void collectDurationPromise('validatePreconditions', require('./lib/startup/validatePreconditions'))()
void collectDurationPromise('cleanupFtpFolder', require('./lib/startup/cleanupFtpFolder'))()
void collectDurationPromise('validateConfig', require('./lib/startup/validateConfig'))({})

// Reloads the i18n files in case of server restarts or starts.
async function restoreOverwrittenFilesWithOriginals () {
  await collectDurationPromise('restoreOverwrittenFilesWithOriginals', require('./lib/startup/restoreOverwrittenFilesWithOriginals'))()
}

/* Sets view engine to hbs */
app.set('view engine', 'hbs')

// Function called first to ensure that all the i18n files are reloaded successfully before other linked operations.
restoreOverwrittenFilesWithOriginals().then(() => {
  /* Locals */
  app.locals.captchaId = 0
  app.locals.captchaReqId = 1
  app.locals.captchaBypassReqTimes = []
  app.locals.abused_ssti_bug = false
  app.locals.abused_ssrf_bug = false

  /* Compression for all requests */
  app.use(compression())

  /* Bludgeon solution for possible CORS problems: Allow everything! */
  app.options('*', cors())
  app.use(cors())

  /* Security middleware */
  app.use(helmet.noSniff())
  app.use(helmet.frameguard())
  // app.use(helmet.xssFilter()); // = no protection from persisted XSS via RESTful API
  app.disable('x-powered-by')
  app.use(featurePolicy({
    features: {
      payment: ["'self'"]
    }
  }))

  /* Hiring header */
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.append('X-Recruiting', config.get('application.securityTxt.hiring'))
    next()
  })

  /* Remove duplicate slashes from URL which allowed bypassing subsequent filters */
  app.use((req: Request, res: Response, next: NextFunction) => {
    req.url = req.url.replace(/[/]+/g, '/')
    next()
  })

  /* Increase request counter metric for every request */
  app.use(metrics.observeRequestMetricsMiddleware())

  /* Security Policy */
  const securityTxtExpiration = new Date()
  securityTxtExpiration.setFullYear(securityTxtExpiration.getFullYear() + 1)
  app.get(['/.well-known/security.txt', '/security.txt'], verify.accessControlChallenges())
  app.use(['/.well-known/security.txt', '/security.txt'], securityTxt({
    contact: config.get('application.securityTxt.contact'),
    encryption: config.get('application.securityTxt.encryption'),
    acknowledgements: config.get('application.securityTxt.acknowledgements'),
    /**
     * Extracts the first two letters (representing languages) from an array of locale objects, eliminates any duplicates, 
     * and joins them into a single, comma-separated string value.
     * 
     * @param {Array} locales - An array of locale objects, each of which has a property named 'key' that includes a language code.
     * @returns {String} Returns a string of unique, 2-letter language codes separated by commas.
     */
    'Preferred-Languages': [...new Set(locales.map((locale: { key: string }) => locale.key.substr(0, 2)))].join(', '),
    hiring: config.get('application.securityTxt.hiring'),
    expires: securityTxtExpiration.toUTCString()
  }))

  /* robots.txt */
  app.use(robots({ UserAgent: '*', Disallow: '/ftp' }))

  /* Checks for challenges solved by retrieving a file implicitly or explicitly */
  app.use('/assets/public/images/padding', verify.accessControlChallenges())
  app.use('/assets/public/images/products', verify.accessControlChallenges())
  app.use('/assets/public/images/uploads', verify.accessControlChallenges())
  app.use('/assets/i18n', verify.accessControlChallenges())

  /* Checks for challenges solved by abusing SSTi and SSRF bugs */
  app.use('/solve/challenges/server-side', verify.serverSideChallenges())

  /* Create middleware to change paths from the serve-index plugin from absolute to relative */
  const serveIndexMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const origEnd = res.end
    // @ts-expect-error
    res.end = function () {
      if (arguments.length) {
        const reqPath = req.originalUrl.replace(/\?.*$/, '')
        const currentFolder = reqPath.split('/').pop() as string
        /**
         * This method modifies HTML anchor tags in a string by altering the href attribute to represent the relative path 
           of the provided URL, based upon the current path request.
         *
         * @param {string} arguments[0] - The string that contains HTML to have its anchor tags href attributes altered.
         *
         * @returns {string} The input string, but with hrefs altered to be relative paths.
         */
        arguments[0] = arguments[0].replace(/a href="([^"]+?)"/gi, function (matchString: string, matchedUrl: string) {
          let relativePath = path.relative(reqPath, matchedUrl)
          if (relativePath === '') {
            relativePath = currentFolder
          } else if (!relativePath.startsWith('.') && currentFolder !== '') {
            relativePath = currentFolder + '/' + relativePath
          } else {
            relativePath = relativePath.replace('..', '.')
          }
          return 'a href="' + relativePath + '"'
        })
      }
      // @ts-expect-error
      origEnd.apply(this, arguments)
    }
    next()
  }

  // vuln-code-snippet start directoryListingChallenge accessLogDisclosureChallenge
  /* /ftp directory browsing and file download */ // vuln-code-snippet neutral-line directoryListingChallenge
  app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true })) // vuln-code-snippet vuln-line directoryListingChallenge
  app.use('/ftp(?!/quarantine)/:file', fileServer()) // vuln-code-snippet vuln-line directoryListingChallenge
  app.use('/ftp/quarantine/:file', quarantineServer()) // vuln-code-snippet neutral-line directoryListingChallenge

  /* /encryptionkeys directory browsing */
  app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', { icons: true, view: 'details' }))
  app.use('/encryptionkeys/:file', keyServer())

  /* /logs directory browsing */ // vuln-code-snippet neutral-line accessLogDisclosureChallenge
  app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', { icons: true, view: 'details' })) // vuln-code-snippet vuln-line accessLogDisclosureChallenge
  app.use('/support/logs', verify.accessControlChallenges()) // vuln-code-snippet hide-line
  app.use('/support/logs/:file', logFileServer()) // vuln-code-snippet vuln-line accessLogDisclosureChallenge

  /* Swagger documentation for B2B v2 endpoints */
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))

  app.use(express.static(path.resolve('frontend/dist/frontend')))
  app.use(cookieParser('kekse'))
  // vuln-code-snippet end directoryListingChallenge accessLogDisclosureChallenge

  /* Configure and enable backend-side i18n */
  i18n.configure({
    /**
     * Method maps through given locales and returns the keys.
     * @param {array}  locales - An array of locale objects, each object should have a 'key' property of type string. 
     * @returns {array} Array of keys from the passed locale objects.
     */
    locales: locales.map((locale: { key: string }) => locale.key),
    directory: path.resolve('i18n'),
    cookie: 'language',
    defaultLocale: 'en',
    autoReload: true
  })
  app.use(i18n.init)

  app.use(bodyParser.urlencoded({ extended: true }))
  /* File Upload */
  app.post('/file-upload', uploadToMemory.single('file'), ensureFileIsPassed, metrics.observeFileUploadMetricsMiddleware(), handleZipFileUpload, checkUploadSize, checkFileType, handleXmlUpload)
  app.post('/profile/image/file', uploadToMemory.single('file'), ensureFileIsPassed, metrics.observeFileUploadMetricsMiddleware(), profileImageFileUpload())
  app.post('/profile/image/url', uploadToMemory.single('file'), profileImageUrlUpload())
  app.post('/rest/memories', uploadToDisk.single('image'), ensureFileIsPassed, security.appendUserId(), metrics.observeFileUploadMetricsMiddleware(), memory.addMemory())

  app.use(bodyParser.text({ type: '*/*' }))
  /**
   * Express middleware for parsing JSON bodies from requests. The original JSON body is preserved in request's rawBody property. 
   * If the request's headers include 'application/json' and body exists, it is parsed and replaced.  
   * If the body content is not a JSON, it's tried to be parsed into a JSON.
   * 
   * @param {Request} req - The request object
   * @param {Response} res - The response object
   * @param {NextFunction} next - The next middleware function to call
   * @returns {void} Middleware does not return anything
   */
  app.use(function jsonParser (req: Request, res: Response, next: NextFunction) {
    // @ts-expect-error
    req.rawBody = req.body
    if (req.headers['content-type']?.includes('application/json')) {
      if (!req.body) {
        req.body = {}
      }
      if (req.body !== Object(req.body)) { // Expensive workaround for 500 errors during Frisby test run (see #640)
        req.body = JSON.parse(req.body)
      }
    }
    next()
  })

  /* HTTP request logging */
  const accessLogStream = require('file-stream-rotator').getStream({
    filename: path.resolve('logs/access.log'),
    frequency: 'daily',
    verbose: false,
    max_logs: '2d'
  })
  app.use(morgan('combined', { stream: accessLogStream }))

  // vuln-code-snippet start resetPasswordMortyChallenge
  /* Rate limiting */
  app.enable('trust proxy')
  app.use('/rest/user/reset-password', new RateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
    keyGenerator ({ headers, ip }: { headers: any, ip: any }) { return headers['X-Forwarded-For'] || ip } // vuln-code-snippet vuln-line resetPasswordMortyChallenge
  }))
  // vuln-code-snippet end resetPasswordMortyChallenge

  // vuln-code-snippet start changeProductChallenge
  /** Authorization **/
  /* Checks on JWT in Authorization header */ // vuln-code-snippet hide-line
  app.use(verify.jwtChallenges()) // vuln-code-snippet hide-line
  /* Baskets: Unauthorized users are not allowed to access baskets */
  app.use('/rest/basket', security.isAuthorized(), security.appendUserId())
  /* BasketItems: API only accessible for authenticated users */
  app.use('/api/BasketItems', security.isAuthorized())
  app.use('/api/BasketItems/:id', security.isAuthorized())
  /* Feedbacks: GET allowed for feedback carousel, POST allowed in order to provide feedback without being logged in */
  app.use('/api/Feedbacks/:id', security.isAuthorized())
  /* Users: Only POST is allowed in order to register a new user */
  app.get('/api/Users', security.isAuthorized())
  app.route('/api/Users/:id')
    .get(security.isAuthorized())
    .put(security.denyAll())
    .delete(security.denyAll())
  /* Products: Only GET is allowed in order to view products */ // vuln-code-snippet neutral-line changeProductChallenge
  app.post('/api/Products', security.isAuthorized()) // vuln-code-snippet neutral-line changeProductChallenge
  // app.put('/api/Products/:id', security.isAuthorized()) // vuln-code-snippet vuln-line changeProductChallenge
  app.delete('/api/Products/:id', security.denyAll())
  /* Challenges: GET list of challenges allowed. Everything else forbidden entirely */
  app.post('/api/Challenges', security.denyAll())
  app.use('/api/Challenges/:id', security.denyAll())
  /* Complaints: POST and GET allowed when logged in only */
  app.get('/api/Complaints', security.isAuthorized())
  app.post('/api/Complaints', security.isAuthorized())
  app.use('/api/Complaints/:id', security.denyAll())
  /* Recycles: POST and GET allowed when logged in only */
  app.get('/api/Recycles', recycles.blockRecycleItems())
  app.post('/api/Recycles', security.isAuthorized())
  /* Challenge evaluation before finale takes over */
  app.get('/api/Recycles/:id', recycles.getRecycleItem())
  app.put('/api/Recycles/:id', security.denyAll())
  app.delete('/api/Recycles/:id', security.denyAll())
  /* SecurityQuestions: Only GET list of questions allowed. */
  app.post('/api/SecurityQuestions', security.denyAll())
  app.use('/api/SecurityQuestions/:id', security.denyAll())
  /* SecurityAnswers: Only POST of answer allowed. */
  app.get('/api/SecurityAnswers', security.denyAll())
  app.use('/api/SecurityAnswers/:id', security.denyAll())
  /* REST API */
  app.use('/rest/user/authentication-details', security.isAuthorized())
  app.use('/rest/basket/:id', security.isAuthorized())
  app.use('/rest/basket/:id/order', security.isAuthorized())
  /* Challenge evaluation before finale takes over */ // vuln-code-snippet hide-start
  app.post('/api/Feedbacks', verify.forgedFeedbackChallenge())
  /* Captcha verification before finale takes over */
  app.post('/api/Feedbacks', captcha.verifyCaptcha())
  /* Captcha Bypass challenge verification */
  app.post('/api/Feedbacks', verify.captchaBypassChallenge())
  /* User registration challenge verifications before finale takes over */
  app.post('/api/Users', (req: Request, res: Response, next: NextFunction) => {
    if (req.body.email !== undefined && req.body.password !== undefined && req.body.passwordRepeat !== undefined) {
      if (req.body.email.length !== 0 && req.body.password.length !== 0) {
        req.body.email = req.body.email.trim()
        req.body.password = req.body.password.trim()
        req.body.passwordRepeat = req.body.passwordRepeat.trim()
      } else {
        res.status(400).send(res.__('Invalid email/password cannot be empty'))
      }
    }
    next()
  })
  app.post('/api/Users', verify.registerAdminChallenge())
  app.post('/api/Users', verify.passwordRepeatChallenge()) // vuln-code-snippet hide-end
  app.post('/api/Users', verify.emptyUserRegistration())
  /* Unauthorized users are not allowed to access B2B API */
  app.use('/b2b/v2', security.isAuthorized())
  /* Check if the quantity is available in stock and limit per user not exceeded, then add item to basket */
  app.put('/api/BasketItems/:id', security.appendUserId(), basketItems.quantityCheckBeforeBasketItemUpdate())
  app.post('/api/BasketItems', security.appendUserId(), basketItems.quantityCheckBeforeBasketItemAddition(), basketItems.addBasketItem())
  /* Accounting users are allowed to check and update quantities */
  app.delete('/api/Quantitys/:id', security.denyAll())
  app.post('/api/Quantitys', security.denyAll())
  app.use('/api/Quantitys/:id', security.isAccounting(), ipfilter(['123.456.789'], { mode: 'allow' }))
  /* Feedbacks: Do not allow changes of existing feedback */
  app.put('/api/Feedbacks/:id', security.denyAll())
  /* PrivacyRequests: Only allowed for authenticated users */
  app.use('/api/PrivacyRequests', security.isAuthorized())
  app.use('/api/PrivacyRequests/:id', security.isAuthorized())
  /* PaymentMethodRequests: Only allowed for authenticated users */
  app.post('/api/Cards', security.appendUserId())
  app.get('/api/Cards', security.appendUserId(), payment.getPaymentMethods())
  app.put('/api/Cards/:id', security.denyAll())
  app.delete('/api/Cards/:id', security.appendUserId(), payment.delPaymentMethodById())
  app.get('/api/Cards/:id', security.appendUserId(), payment.getPaymentMethodById())
  /* PrivacyRequests: Only POST allowed for authenticated users */
  app.post('/api/PrivacyRequests', security.isAuthorized())
  app.get('/api/PrivacyRequests', security.denyAll())
  app.use('/api/PrivacyRequests/:id', security.denyAll())

  app.post('/api/Addresss', security.appendUserId())
  app.get('/api/Addresss', security.appendUserId(), address.getAddress())
  app.put('/api/Addresss/:id', security.appendUserId())
  app.delete('/api/Addresss/:id', security.appendUserId(), address.delAddressById())
  app.get('/api/Addresss/:id', security.appendUserId(), address.getAddressById())
  app.get('/api/Deliverys', delivery.getDeliveryMethods())
  app.get('/api/Deliverys/:id', delivery.getDeliveryMethod())
  // vuln-code-snippet end changeProductChallenge

  /* Verify the 2FA Token */
  app.post('/rest/2fa/verify',
    new RateLimit({ windowMs: 5 * 60 * 1000, max: 100 }),
    twoFactorAuth.verify()
  )
  /* Check 2FA Status for the current User */
  app.get('/rest/2fa/status', security.isAuthorized(), twoFactorAuth.status())
  /* Enable 2FA for the current User */
  app.post('/rest/2fa/setup',
    new RateLimit({ windowMs: 5 * 60 * 1000, max: 100 }),
    security.isAuthorized(),
    twoFactorAuth.setup()
  )
  /* Disable 2FA Status for the current User */
  app.post('/rest/2fa/disable',
    new RateLimit({ windowMs: 5 * 60 * 1000, max: 100 }),
    security.isAuthorized(),
    twoFactorAuth.disable()
  )
  /* Verifying DB related challenges can be postponed until the next request for challenges is coming via finale */
  app.use(verify.databaseRelatedChallenges())

  // vuln-code-snippet start registerAdminChallenge
  /* Generated API endpoints */
  finale.initialize({ app, sequelize })

  const autoModels = [
    { name: 'User', exclude: ['password', 'totpSecret'], model: UserModel },
    { name: 'Product', exclude: [], model: ProductModel },
    { name: 'Feedback', exclude: [], model: FeedbackModel },
    { name: 'BasketItem', exclude: [], model: BasketItemModel },
    { name: 'Challenge', exclude: [], model: ChallengeModel },
    { name: 'Complaint', exclude: [], model: ComplaintModel },
    { name: 'Recycle', exclude: [], model: RecycleModel },
    { name: 'SecurityQuestion', exclude: [], model: SecurityQuestionModel },
    { name: 'SecurityAnswer', exclude: [], model: SecurityAnswerModel },
    { name: 'Address', exclude: [], model: AddressModel },
    { name: 'PrivacyRequest', exclude: [], model: PrivacyRequestModel },
    { name: 'Card', exclude: [], model: CardModel },
    { name: 'Quantity', exclude: [], model: QuantityModel }
  ]

  for (const { name, exclude, model } of autoModels) {
    const resource = finale.resource({
      model,
      endpoints: [`/api/${name}s`, `/api/${name}s/:id`],
      excludeAttributes: exclude,
      pagination: false
    })

    // create a wallet when a new user is registered using API
    if (name === 'User') { // vuln-code-snippet neutral-line registerAdminChallenge
      resource.create.send.before((req: Request, res: Response, context: { instance: { id: any }, continue: any }) => { // vuln-code-snippet vuln-line registerAdminChallenge
        WalletModel.create({ UserId: context.instance.id }).catch((err: unknown) => {
          console.log(err)
        })
        return context.continue // vuln-code-snippet neutral-line registerAdminChallenge
      }) // vuln-code-snippet neutral-line registerAdminChallenge
    } // vuln-code-snippet neutral-line registerAdminChallenge
    // vuln-code-snippet end registerAdminChallenge

    // translate challenge descriptions and hints on-the-fly
    if (name === 'Challenge') {
      /**
       * This method executes after the fetch operation on the resource list. It iterates over 
       * the instances in the context, translates the "description" and "hint" properties 
       * of each instance if they exist.
       * The method dimensions any warning present in the description text.
       * @param {Request} req - The request object from the client.
       * @param {Response} res - The response object to be sent to the client.
       * @param {Object} context - An object that holds multiple properties including an 
       * instance, which could be a string or an array and a continue method.
       * @returns {Function} It returns the continue method from the context.
       */
      resource.list.fetch.after((req: Request, res: Response, context: { instance: string | any[], continue: any }) => {
        for (let i = 0; i < context.instance.length; i++) {
          let description = context.instance[i].description
          if (utils.contains(description, '<em>(This challenge is <strong>')) {
            const warning = description.substring(description.indexOf(' <em>(This challenge is <strong>'))
            description = description.substring(0, description.indexOf(' <em>(This challenge is <strong>'))
            context.instance[i].description = req.__(description) + req.__(warning)
          } else {
            context.instance[i].description = req.__(description)
          }
          if (context.instance[i].hint) {
            context.instance[i].hint = req.__(context.instance[i].hint)
          }
        }
        return context.continue
      })
      /**
       * A middleware function for pre-process data before sending a read request.
       * It translates the description and hint properties based on the user's locale.
       *
       * @param {Request}  req - The Express request object.
       * @param {Response} res - The Express response object.
       * @param {Object} context - context object contains instance (with 'description' and 'hint' properties) and 'continue' function.
       * @param {Object} context.instance - The instance containing the description and hint to be processed.
       * @param {string} context.instance.description - The description to be processed.
       * @param {string} context.instance.hint - The hint to be processed. This is optional.
       * @param {Function} context.continue - The next function to be called.
       *
       * @returns {Function} The modified 'continue' function.
       */
      resource.read.send.before((req: Request, res: Response, context: { instance: { description: string, hint: string }, continue: any }) => {
        context.instance.description = req.__(context.instance.description)
        if (context.instance.hint) {
          context.instance.hint = req.__(context.instance.hint)
        }
        return context.continue
      })
    }

    // translate security questions on-the-fly
    if (name === 'SecurityQuestion') {
      /**
       * Fetch method for the resource list which runs after the base operation. 
       * It iterates over the items in the context instance and modifies each item by setting the value of 'question' key.
       * @param {Object}  req - Request object.
       * @param {Object}  res - Response object.
       * @param {Object}  context - Context object with 'instance' key which could be a string or an array, and 'continue' key which is a callback function.
       * @returns {Function} Returns the 'continue' callback function from the context object.
       */
      resource.list.fetch.after((req: Request, res: Response, context: { instance: string | any[], continue: any }) => {
        for (let i = 0; i < context.instance.length; i++) {
          context.instance[i].question = req.__(context.instance[i].question)
        }
        return context.continue
      })
      /**
       * Middleware function to manipulate the question string in the instance context before executing a GET request.
       * @param {Request} req - The HTTP request object.
       * @param {Response} res - The HTTP response object.
       * @param {Object} context - The context object of the current instance, it contains the instance itself and the continue function. The instance has a question property.
       * @returns {Function} The unchanged continue function from the context object.
       */
      resource.read.send.before((req: Request, res: Response, context: { instance: { question: string }, continue: any }) => {
        context.instance.question = req.__(context.instance.question)
        return context.continue
      })
    }

    // translate product names and descriptions on-the-fly
    if (name === 'Product') {
      /**
       * This method is a post-processing operation for the list.fetch API call. It loops over the returned data instances and modifies the name and description of each instance based on a provided request function.
       * @param {Object} req - The request object, containing functions to modify the name and description of a data instance.
       * @param {Object} res - The response object.
       * @param {Object} context - The context object, which contains the instances returned by list.fetch API call and the continue method.
       * @returns {Function} The 'continue' method that can be chained with other operations.
       */
      resource.list.fetch.after((req: Request, res: Response, context: { instance: any[], continue: any }) => {
        for (let i = 0; i < context.instance.length; i++) {
          context.instance[i].name = req.__(context.instance[i].name)
          context.instance[i].description = req.__(context.instance[i].description)
        }
        return context.continue
      })
      /**
       * This middleware function intercepts a "read" request before it is executed, alters the request instance with localized values extracted from the request object, and then proceeds with the execution.
       * @param {Request} req - The Express Request Object.
       * @param {Response} res - The Express Response Object.
       * @param {Object} context - Contains the "instance" object to be modified and the "continue" function to proceed with the request execution.
       * @param {Object} context.instance - The instance to be modified; it should have at least the "name" and "description" properties.
       * @param {Function} context.continue - The function to be called to proceed with the execution of the incoming request.
       * @returns {Function} The proceed function to continue execution.
       */
      resource.read.send.before((req: Request, res: Response, context: { instance: { name: string, description: string }, continue: any }) => {
        context.instance.name = req.__(context.instance.name)
        context.instance.description = req.__(context.instance.description)
        return context.continue
      })
    }

    // fix the api difference between finale (fka epilogue) and previously used sequlize-restful
    resource.all.send.before((req: Request, res: Response, context: { instance: { status: string, data: any }, continue: any }) => {
      context.instance = {
        status: 'success',
        data: context.instance
      }
      return context.continue
    })
  }

  /* Custom Restful API */
  app.post('/rest/user/login', login())
  app.get('/rest/user/change-password', changePassword())
  app.post('/rest/user/reset-password', resetPassword())
  app.get('/rest/user/security-question', securityQuestion())
  app.get('/rest/user/whoami', security.updateAuthenticatedUsers(), currentUser())
  app.get('/rest/user/authentication-details', authenticatedUsers())
  app.get('/rest/products/search', search())
  app.get('/rest/basket/:id', basket())
  app.post('/rest/basket/:id/checkout', order())
  app.put('/rest/basket/:id/coupon/:coupon', coupon())
  app.get('/rest/admin/application-version', appVersion())
  app.get('/rest/admin/application-configuration', appConfiguration())
  app.get('/rest/repeat-notification', repeatNotification())
  app.get('/rest/continue-code', continueCode.continueCode())
  app.get('/rest/continue-code-findIt', continueCode.continueCodeFindIt())
  app.get('/rest/continue-code-fixIt', continueCode.continueCodeFixIt())
  app.put('/rest/continue-code-findIt/apply/:continueCode', restoreProgress.restoreProgressFindIt())
  app.put('/rest/continue-code-fixIt/apply/:continueCode', restoreProgress.restoreProgressFixIt())
  app.put('/rest/continue-code/apply/:continueCode', restoreProgress.restoreProgress())
  app.get('/rest/admin/application-version', appVersion())
  app.get('/rest/captcha', captcha())
  app.get('/rest/image-captcha', imageCaptcha())
  app.get('/rest/track-order/:id', trackOrder())
  app.get('/rest/country-mapping', countryMapping())
  app.get('/rest/saveLoginIp', saveLoginIp())
  app.post('/rest/user/data-export', security.appendUserId(), imageCaptcha.verifyCaptcha())
  app.post('/rest/user/data-export', security.appendUserId(), dataExport())
  app.get('/rest/languages', languageList())
  app.get('/rest/order-history', orderHistory.orderHistory())
  app.get('/rest/order-history/orders', security.isAccounting(), orderHistory.allOrders())
  app.put('/rest/order-history/:id/delivery-status', security.isAccounting(), orderHistory.toggleDeliveryStatus())
  app.get('/rest/wallet/balance', security.appendUserId(), wallet.getWalletBalance())
  app.put('/rest/wallet/balance', security.appendUserId(), wallet.addWalletBalance())
  app.get('/rest/deluxe-membership', deluxe.deluxeMembershipStatus())
  app.post('/rest/deluxe-membership', security.appendUserId(), deluxe.upgradeToDeluxe())
  app.get('/rest/memories', memory.getMemories())
  app.get('/rest/chatbot/status', chatbot.status())
  app.post('/rest/chatbot/respond', chatbot.process())
  /* NoSQL API endpoints */
  app.get('/rest/products/:id/reviews', showProductReviews())
  app.put('/rest/products/:id/reviews', createProductReviews())
  app.patch('/rest/products/reviews', security.isAuthorized(), updateProductReviews())
  app.post('/rest/products/reviews', security.isAuthorized(), likeProductReviews())

  /* B2B Order API */
  app.post('/b2b/v2/orders', b2bOrder())

  /* File Serving */
  app.get('/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg', easterEgg())
  app.get('/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us', premiumReward())
  app.get('/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility', privacyPolicyProof())

  /* Route for dataerasure page */
  app.use('/dataerasure', dataErasure)

  /* Route for redirects */
  app.get('/redirect', redirect())

  /* Routes for promotion video page */
  app.get('/promotion', videoHandler.promotionVideo())
  app.get('/video', videoHandler.getVideo())

  /* Routes for profile page */
  app.get('/profile', security.updateAuthenticatedUsers(), userProfile())
  app.post('/profile', updateUserProfile())

  /* Route for vulnerable code snippets */
  app.get('/snippets', vulnCodeSnippet.serveChallengesWithCodeSnippet())
  app.get('/snippets/:challenge', vulnCodeSnippet.serveCodeSnippet())
  app.post('/snippets/verdict', vulnCodeSnippet.checkVulnLines())
  app.get('/snippets/fixes/:key', vulnCodeFixes.serveCodeFixes())
  app.post('/snippets/fixes', vulnCodeFixes.checkCorrectFix())

  app.use(angular())

  /* Error Handling */
  app.use(verify.errorHandlingChallenge())
  app.use(errorhandler())
/**
 * Handle promise errors
 * @param {Error} err - An error object describing what went wrong
 */

}).catch((err) => {
  console.error(err)
})

const multer = require('multer')
const uploadToMemory = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200000 } })
const mimeTypeMap: any = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg'
}
const uploadToDisk = multer({
  storage: multer.diskStorage({
    /**
     * This method defines the destination path for uploaded file. It also validates the mime type of the uploaded file.
     * @param {Request} req - The incoming request object.
     * @param {any} file - The file that needs to be uploaded.
     * @param {Function} cb - The callback function to be invoked after validating mime type and defining destination path.
     * @returns {void} This method does not have a return value but it calls the callback function with error (if any) and destination path as arguments.
     */
    destination: (req: Request, file: any, cb: Function) => {
      const isValid = mimeTypeMap[file.mimetype]
      let error: Error | null = new Error('Invalid mime type')
      if (isValid) {
        error = null
      }
      cb(error, path.resolve('frontend/dist/frontend/assets/public/images/uploads/'))
    },
    /**
     * Method to sanitise and standardise the file name while uploading. It converts the filename to lowercase, replaces spaces with dashes, appends current timestamp and adds correct extension based on mimetype.
     * @param {Request} req - The express Request object.
     * @param {any} file - Object containing information and data of the file to be uploaded.
     * @param {Function} cb - Callback function to execute after file name is generated and sanitised.
     * @returns {void} This method does not have a return. The result is sent through the callback function.
     */
    filename: (req: Request, file: any, cb: Function) => {
      const name = security.sanitizeFilename(file.originalname)
        .toLowerCase()
        .split(' ')
        .join('-')
      const ext = mimeTypeMap[file.mimetype]
      cb(null, name + '-' + Date.now() + '.' + ext)
    }
  })
})

const expectedModels = ['Address', 'Basket', 'BasketItem', 'Captcha', 'Card', 'Challenge', 'Complaint', 'Delivery', 'Feedback', 'ImageCaptcha', 'Memory', 'PrivacyRequestModel', 'Product', 'Quantity', 'Recycle', 'SecurityAnswer', 'SecurityQuestion', 'User', 'Wallet']
/**
 * This snippet continuously checks that all expected models exist within Sequelize's list of defined models.
 * @param {Array} expectedModels - An array of models that are expected to be defined.
 * @param {Object} sequelize.models - An object representing all models defined in sequelize.
 */

while (!expectedModels.every(model => Object.keys(sequelize.models).includes(model))) {
  logger.info(`Entity models ${colors.bold(Object.keys(sequelize.models).length.toString())} of ${colors.bold(expectedModels.length.toString())} are initialized (${colors.yellow('WAITING')})`)
}
logger.info(`Entity models ${colors.bold(Object.keys(sequelize.models).length.toString())} of ${colors.bold(expectedModels.length.toString())} are initialized (${colors.green('OK')})`)

// vuln-code-snippet start exposedMetricsChallenge
/* Serve metrics */
let metricsUpdateLoop: any
const Metrics = metrics.observeMetrics() // vuln-code-snippet neutral-line exposedMetricsChallenge
const customizeEasterEgg = require('./lib/startup/customizeEasterEgg') // vuln-code-snippet hide-line
app.get('/metrics', metrics.serveMetrics()) // vuln-code-snippet vuln-line exposedMetricsChallenge
errorhandler.title = `${config.get('application.name')} (Express ${utils.version('express')})`

const registerWebsocketEvents = require('./lib/startup/registerWebsocketEvents')
const customizeApplication = require('./lib/startup/customizeApplication')

/**
 * Initiates the server and sets up the environment including the database and server port.
 * It also manages the metrics update loop and register websocket events.
 * @param {Function} readyCallback - A callback function to be executed when the setup is ready.
 */
export async function start (readyCallback: Function) {
  const datacreatorEnd = startupGauge.startTimer({ task: 'datacreator' })
  await sequelize.sync({ force: true })
  await datacreator()
  datacreatorEnd()
  const port = process.env.PORT ?? config.get('server.port')
  process.env.BASE_PATH = process.env.BASE_PATH ?? config.get('server.basePath')

  metricsUpdateLoop = Metrics.updateLoop() // vuln-code-snippet neutral-line exposedMetricsChallenge

  /**
   * This method starts a server listening on a specified port and registers websocket events. 
   * It also sets a gauge to monitor startup time and logs the server status and base path if any.
   * @param {number} port - The port number on which the server is to listen.
   * @param {function} readyCallback - The callback function to be invoked once the server is ready.
   * @returns {void} This function does not return anything
   */
  server.listen(port, () => {
    logger.info(colors.cyan(`Server listening on port ${colors.bold(`${port}`)}`))
    startupGauge.set({ task: 'ready' }, (Date.now() - startTime) / 1000)
    if (process.env.BASE_PATH !== '') {
      logger.info(colors.cyan(`Server using proxy base path ${colors.bold(`${process.env.BASE_PATH}`)} for redirects`))
    }
    registerWebsocketEvents(server)
    if (readyCallback) {
      readyCallback()
    }
  })

  void collectDurationPromise('customizeApplication', customizeApplication)() // vuln-code-snippet hide-line
  void collectDurationPromise('customizeEasterEgg', customizeEasterEgg)() // vuln-code-snippet hide-line
}

/**
 * The function closes the server and terminates the process with a specified exit code if one is provided.
 * @param {number | undefined} exitCode - An optional exit code. If specified, the process exits with the provided code.
 */
export function close (exitCode: number | undefined) {
  if (server) {
    clearInterval(metricsUpdateLoop)
    server.close()
  }
  if (exitCode !== undefined) {
    process.exit(exitCode)
  }
}
// vuln-code-snippet end exposedMetricsChallenge

// stop server on sigint or sigterm signals
process.on('SIGINT', () => close(0))
/**
 * Listens for a termination signal (SIGTERM) and calls the close function with 0 as parameter when it occurs.
 * This method is especially useful for graceful shutdown in applications.
 */
process.on('SIGTERM', () => close(0))
