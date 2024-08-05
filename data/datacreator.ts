/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import { AddressModel } from '../models/address'
import { BasketModel } from '../models/basket'
import { BasketItemModel } from '../models/basketitem'
import { CardModel } from '../models/card'
import { ChallengeModel } from '../models/challenge'
import { ComplaintModel } from '../models/complaint'
import { DeliveryModel } from '../models/delivery'
import { FeedbackModel } from '../models/feedback'
import { MemoryModel } from '../models/memory'
import { ProductModel } from '../models/product'
import { QuantityModel } from '../models/quantity'
import { RecycleModel } from '../models/recycle'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { SecurityQuestionModel } from '../models/securityQuestion'
import { UserModel } from '../models/user'
import { WalletModel } from '../models/wallet'
import { Address, Card, Challenge, Delivery, Memory, Product, SecurityQuestion, User } from './types'
import logger from '../lib/logger'
import config from 'config'
import path from 'path'
import * as utils from '../lib/utils'
const datacache = require('./datacache')
const mongodb = require('./mongodb')
const security = require('../lib/insecurity')

const fs = require('fs')
const util = require('util')
const { safeLoad } = require('js-yaml')
const Entities = require('html-entities').AllHtmlEntities
const entities = new Entities()

const readFile = util.promisify(fs.readFile)

/**
 * Function to load the static data from a specified file.
 * @param {string} file - Name of the file from which the static data needs to be loaded.
 * @returns {Promise<string>} Returns a promise that resolves with the contents of the file as a string, or logs an error if the file could not be opened.
 */
function loadStaticData (file: string) {
  const filePath = path.resolve('./data/static/' + file + '.yml')
  return readFile(filePath, 'utf8')
    .then(safeLoad)
    /**
     * Logs error related to the unsuccessful opening of a file in the system
     * @param {string} filePath - Represents the path of the file to be opened
     * @returns {undefined} No return
     */
    .catch(() => logger.error('Could not open file: "' + filePath + '"'))
}

/**
 * The function exports all creator methods. These creator methods are used in creating different items i.e., SecurityQuestions, Users, Challenges, RandomFakeUsers, Products, Baskets, BasketItems, AnonymousFeedback, Complaints, RecycleItems, Orders, Quantity, Wallet, DeliveryMethods, and Memories. Each creator function is called iteratively in a sequential order.
 * @returns {Promise} This asynchronous function does not explicitly return a value but it ensures all creation functions get executed in series.
 */
module.exports = async () => {
  const creators = [
    createSecurityQuestions,
    createUsers,
    createChallenges,
    createRandomFakeUsers,
    createProducts,
    createBaskets,
    createBasketItems,
    createAnonymousFeedback,
    createComplaints,
    createRecycleItem,
    createOrders,
    createQuantity,
    createWallet,
    createDeliveryMethods,
    createMemories
  ]

  for (const creator of creators) {
    await creator()
  }
}

/**
 * Asynchronous function to create challenges, applying configurations, and handle error.
 * It loads static data for challenges, replaces sensitive data, and then inserts these challenges into the data cache.
 * This function directly does not take any parameters but uses global variables like config, entities, logger, datacache.
 * @returns {Promise<void>} Returns a Promise that resolves to undefined when all challenges have been successfully created.
 */
async function createChallenges () {
  const showHints = config.get('challenges.showHints')
  const showMitigations = config.get('challenges.showMitigations')

  const challenges = await loadStaticData('challenges')

  await Promise.all(
    /**
     * Maps through the challenges array and creates a new ChallengeModel instance for each challenge. 
     * It also manipulates the description and hint of the challenge based on the application's configurations. 
     * It also handles any errors that occur during the creation of the ChallengeModel instance.
     * @param {Object} Challenge - An object representing a Challenge with properties name, category, description, difficulty, hint, hintUrl, mitigationUrl, key, disabledEnv, tutorial, tags.
     * @returns {Promise} Returns a promise that resolves when all ChallengeModel instances have been created successfully, and rejects if an error occurs.
     */
    challenges.map(async ({ name, category, description, difficulty, hint, hintUrl, mitigationUrl, key, disabledEnv, tutorial, tags }: Challenge) => {
      const effectiveDisabledEnv = utils.determineDisabledEnv(disabledEnv)
      description = description.replace('juice-sh.op', config.get('application.domain'))
      description = description.replace('&lt;iframe width=&quot;100%&quot; height=&quot;166&quot; scrolling=&quot;no&quot; frameborder=&quot;no&quot; allow=&quot;autoplay&quot; src=&quot;https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&amp;color=%23ff5500&amp;auto_play=true&amp;hide_related=false&amp;show_comments=true&amp;show_user=true&amp;show_reposts=false&amp;show_teaser=true&quot;&gt;&lt;/iframe&gt;', entities.encode(config.get('challenges.xssBonusPayload')))
      hint = hint.replace(/OWASP Juice Shop's/, `${config.get('application.name')}'s`)

      try {
        datacache.challenges[key] = await ChallengeModel.create({
          key,
          name,
          category,
          tags: tags ? tags.join(',') : undefined,
          description: effectiveDisabledEnv ? (description + ' <em>(This challenge is <strong>' + (config.get('challenges.safetyOverride') ? 'potentially harmful' : 'not available') + '</strong> on ' + effectiveDisabledEnv + '!)</em>') : description,
          difficulty,
          solved: false,
          hint: showHints ? hint : null,
          hintUrl: showHints ? hintUrl : null,
          mitigationUrl: showMitigations ? mitigationUrl : null,
          disabledEnv: config.get<boolean>('challenges.safetyOverride') ? null : effectiveDisabledEnv,
          tutorialOrder: tutorial ? tutorial.order : null,
          codingChallengeStatus: 0
        })
      } catch (err) {
        logger.error(`Could not insert Challenge ${name}: ${utils.getErrorMessage(err)}`)
      }
    })
  )
}

/**
 * This function is used to create user entries asynchronously by loading static data for users.
 * It further processes these loaded users and creates user entries in the database along with their associated fields if available.
 * The associated fields can be security answer, feedback, address, or card. Also, checks for the deleted user flag.
 * Error handling is also done in case of any errors while creating users.
 * @returns {Promise<void>} Returns a promise which resolves when all the users have been processed, but doesn't return any value.
 */
async function createUsers () {
  const users = await loadStaticData('users')

  await Promise.all(
    /**
     * This asynchronous method takes in a map of user data and performs multiple operations on the data. 
     * It creates a new user with the provided details, sets up security answers if provided and creates feedback, addresses, and cards if they're available too.
     * If any error occurs during the operation, it logs the error with the corresponding user key.
     * 
     * @param {Object} User - An object encapsulating multiple properties of a user such as username, email, password, customDomain, key, role, deletedFlag, profileImage, securityQuestion, feedback, address, card, totpSecret, lastLoginIp.
     * @returns {void} This method does not return anything. However, it populates the datacache.users object with the created user accounts keyed by user key.
     */
    users.map(async ({ username, email, password, customDomain, key, role, deletedFlag, profileImage, securityQuestion, feedback, address, card, totpSecret, lastLoginIp = '' }: User) => {
      try {
        const completeEmail = customDomain ? email : `${email}@${config.get('application.domain')}`
        const user = await UserModel.create({
          username,
          email: completeEmail,
          password,
          role,
          deluxeToken: role === security.roles.deluxe ? security.deluxeToken(completeEmail) : '',
          profileImage: `assets/public/images/uploads/${profileImage ?? (role === security.roles.admin ? 'defaultAdmin.png' : 'default.svg')}`,
          totpSecret,
          lastLoginIp
        })
        datacache.users[key] = user
        if (securityQuestion) await createSecurityAnswer(user.id, securityQuestion.id, securityQuestion.answer)
        if (feedback) await createFeedback(user.id, feedback.comment, feedback.rating, user.email)
        if (deletedFlag) await deleteUser(user.id)
        if (address) await createAddresses(user.id, address)
        if (card) await createCards(user.id, card)
      } catch (err) {
        logger.error(`Could not insert User ${key}: ${utils.getErrorMessage(err)}`)
      }
    })
  )
}

/**
 * Asynchronously creates new wallet objects for each user in the provided user data.
 * Utilizes the 'WalletModel' to create and persist each new wallet, setting its 
 * initial balance to the user's 'walletBalance' if provided, otherwise setting it to 0.
 * 
 * @returns {Promise<Array>} An array of Promises each resolving to the persisted WalletModel object for each user.
 */

async function createWallet () {
  const users = await loadStaticData('users')
  return await Promise.all(
    /**
     * Maps over the passed in array of users and asynchronously creates a new WalletModel instance for each user.
     * @param {User} user - The current user object in the mapped array.
     * @param {number} index - The current index in the mapped array.
     * @returns {Promise} A promise which resolves when the WalletModel is successfully created or rejects when an error is caught.
     */
    users.map(async (user: User, index: number) => {
      return await WalletModel.create({
        UserId: index + 1,
        balance: user.walletBalance !== undefined ? user.walletBalance : 0
      /**
       * This method is a part of promise chain, specifically designed to catch any errors that may occur during the promise execution.
       * @param {unknown} err - Error object encapsulating details about the error that occurred in the promise execution.
       * @returns {void} This function does not have a return value. Its sole purpose is to log the error messages to a logging framework.
       */
      }).catch((err: unknown) => {
        logger.error(`Could not create wallet: ${utils.getErrorMessage(err)}`)
      })
    })
  )
}

/**
 * This method acts to create delivery methods by loading a static data file named 'deliveries'.
 * It asynchronously iterates through each delivery object in the file and creates a new model instance
 * based on the properties of each object. If an error occurs during this process, it is logged for future troubleshooting.
 * This function does not take any parameters nor does it return any outputs.
 */
async function createDeliveryMethods () {
  const deliveries = await loadStaticData('deliveries')

  await Promise.all(
    /**
     * Maps over an array of 'Delivery' objects, trying to create each one in the 'DeliveryModel'. 
     * On error, it logs an error message with the error details.
     * @param {Array<Object>} deliveries - Array of delivery details objects.
     * @param {string} deliveries[].name - The name of the delivery method.
     * @param {number} deliveries[].price - The price of the delivery method.
     * @param {number} deliveries[].deluxePrice - The deluxe price of the delivery method.
     * @param {number} deliveries[].eta - The estimated time of arrival for the delivery method.
     * @param {string} deliveries[].icon - The icon representing the delivery method.
     * @returns {Promise<void>} Does not return anything but creates each delivery method in the 'DeliveryModel'.
     */
    deliveries.map(async ({ name, price, deluxePrice, eta, icon }: Delivery) => {
      try {
        await DeliveryModel.create({
          name,
          price,
          deluxePrice,
          eta,
          icon
        })
      } catch (err) {
        logger.error(`Could not insert Delivery Method: ${utils.getErrorMessage(err)}`)
      }
    })
  )
}

/**
 * This function creates multiple addresses for a specific user
 * @param {number}  UserId - The ID of the user for whom to create the addresses
 * @param {Address[]}  addresses - An array of address objects that needs to be created for the user
 * @returns {Promise[]} An array of Promises that represent the creation of addresses. Each Promise resolves to the created address record or rejects with an error message
 */
function createAddresses (UserId: number, addresses: Address[]) {
  /**
   * This method maps over an array of user addresses, and for each address, it creates a new entry in the AddressModel.
   * The method asynchronously awaits the creation of new address in the AddressModel.
   * In the case of an error during the creation of a new address, it logs the error message.
   * @param {Array<Object>}  addresses - An array of address objects. Each address object contains the user's 
   * Country, Full Name, Mobile Number, Zip Code, Street Address, City, and optionally, State.
   * @returns {Promise<Array>} Returns a Promise that resolves to an array of Promises. Each promise 
   * either resolves to the newly created document in the AddressModel or an undefined if there was an error during creation.
   */
  addresses.map(async (address) => {
    return await AddressModel.create({
      UserId: UserId,
      country: address.country,
      fullName: address.fullName,
      mobileNum: address.mobileNum,
      zipCode: address.zipCode,
      streetAddress: address.streetAddress,
      city: address.city,
      state: address.state ? address.state : null
    /**
     * Handles errors while creating addresses.
     * @param {unknown} err - Error thrown when creating addresses.
     * @returns {void} Logs the error message using a logging service.
     */
    }).catch((err: unknown) => {
      logger.error(`Could not create address: ${utils.getErrorMessage(err)}`)
    })
  })
}

/**
 * This asynchronous function creates multiple card instances in the database for a specific user.
 * @param {number}  UserId - The ID of the user for whom the cards are to be created.
 * @param {Array}  cards - An array of Card objects that contains information about each card. Each Card object should have properties: fullName, cardNum, expMonth, expYear.
 * @returns {Array} Returns a promise which resolves into an array of promises, each one representing an attempt to create a card instance in the database. If a card creation fails, an error log is generated.
 */

async function createCards (UserId: number, cards: Card[]) {
  /**
   * This method creates card records for a particular user in the database using async/Promise.all. 
   * For each card in the input array, a new card document is created which contains user ID, card full name, card number, expiry month and year.
   * If there is an error during the creation of the card, an error message is logged.
   * 
   * @param {Array<Object>} cards - An array of card objects. Each card object contains the fullName, cardNumber, expMonth, expYear as attributes.
   * @param {number} UserId - Unique Identifier of the user to whom the card belongs.
   * 
   * @returns {Promise<Array>} Returns a promise that resolves to an array of promises. Each promise represents the outcome of the CardModel.create card creation operation for each card.
   */
  
  return await Promise.all(cards.map(async (card) => {
    return await CardModel.create({
      UserId: UserId,
      fullName: card.fullName,
      cardNum: Number(card.cardNum),
      expMonth: card.expMonth,
      expYear: card.expYear
    /**
     * Error handling function for failed card creation.
     * @param {unknown}  err - The error returned from attempted card creation.
     */
    }).catch((err: unknown) => {
      logger.error(`Could not create card: ${utils.getErrorMessage(err)}`)
    })
  }))
}

/**
 * This function performs the action to delete a user from the UserModel. In case of error, it catches the exception and logs the error message.
 * @param {number}  userId - A unique identifier for the user to be deleted.
 * @returns {Promise} Returns a Promise that resolves if user is successfully deleted or rejects with an error message if an issue occurred.
 */
async function deleteUser (userId: number) {
  /**
   * Destroys a user record from the UserModel.
   * @param {number} userId - The id of the user to delete.
   * @returns {Promise} Promise object represents the result of the deletion operation. Logs error if unsuccessful.
   */
  return await UserModel.destroy({ where: { id: userId } }).catch((err: unknown) => {
    logger.error(`Could not perform soft delete for the user ${userId}: ${utils.getErrorMessage(err)}`)
  })
}

/**
 * A function to delete a specific product from the ProductModel database.
 * @param {number} productId - The ID of the product that is to be deleted.
 * @returns {Promise} Promise represents the completion of an asynchronous operation to delete a product. Returns an error message if the operation fails.
 */
async function deleteProduct (productId: number) {
  /**
   * Deletes a product record from the database identified by the productId. It is a soft delete operation - the data is marked as deleted but not actually removed.
   * @param {number}  productId - Identifier of the product to be deleted.
   * @returns {Promise<number>} The number of affected rows for the delete operation.
   * @throws Will throw an error message logged using logger if any error occurs during the operation.
   */
  
  return await ProductModel.destroy({ where: { id: productId } }).catch((err: unknown) => {
    logger.error(`Could not perform soft delete for the product ${productId}: ${utils.getErrorMessage(err)}`)
  })
}

/**
 * Asynchronous function to create a set of randomly generated fake users.
 * Internally, it generates random fake emails and passwords for each user.
 * This function uses 'UserModel' to create each user.
 *
 * NOTE: This function uses the 'config' value 'application.numberOfRandomFakeUsers' 
 * to determine the number of fake users to create. Ensure you have properly set this configuration value.
 * 
 * @returns {Promise<Array>} An array of promises, each resolving to a newly created random fake user. 
 * Use "Promise.all()" to ensure all users have been created.
 */
async function createRandomFakeUsers () {
  /**
   * Generates a random fake user email. A user email is generated with a random username and a random domain.
   * No parameters are needed for this function and it returns a string.
   * @returns {string} Randomly generated fake user email.
   */
  function getGeneratedRandomFakeUserEmail () {
    const randomDomain = makeRandomString(4).toLowerCase() + '.' + makeRandomString(2).toLowerCase()
    return makeRandomString(5).toLowerCase() + '@' + randomDomain
  }

  /**
   * Generates a random alphanumeric string of a given length.
   * @param {number} length - Length of the random string to be generated.
   * @returns {string} A random alphanumeric string of the given length.
   */
  function makeRandomString (length: number) {
    let text = ''
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

    for (let i = 0; i < length; i++) { text += possible.charAt(Math.floor(Math.random() * possible.length)) }

    return text
  }

  return await Promise.all(new Array(config.get('application.numberOfRandomFakeUsers')).fill(0).map(
    /**
     * Asynchronously creates a new user in the User database model with a randomly generated email and password.
     * @returns {Promise<Object>} Returns a Promise that resolves to the newly created user object.
     */
    async () => await UserModel.create({
      email: getGeneratedRandomFakeUserEmail(),
      password: makeRandomString(5)
    })
  ))
}

/**
 * An asynchronous function that creates quantities for each product in the product configuration. Uses the 'products' object from the config module. For each product, a new Quantity is created and stored in the database. If the quantity of the product is defined, it is used, otherwise a random quantity is used. If there is a limit per user for the product, it is used, otherwise null is used.
 * @param {None} No parameters required.
 * @returns {Promise<Array>} Returns a Promise that resolves to an array of Quantities created.
 */
async function createQuantity () {
  return await Promise.all(
    config.get<Product[]>('products').map(async (product: Product, index: number) => {
      return await QuantityModel.create({
        ProductId: index + 1,
        quantity: product.quantity !== undefined ? product.quantity : Math.floor(Math.random() * 70 + 30),
        limitPerUser: product.limitPerUser ?? null
      }).catch((err: unknown) => {
        logger.error(`Could not create quantity: ${utils.getErrorMessage(err)}`)
      })
    })
  )
}

async function createMemories () {
  const memories = [
    MemoryModel.create({
      imagePath: 'assets/public/images/uploads/😼-#zatschi-#whoneedsfourlegs-1572600969477.jpg',
      caption: '😼 #zatschi #whoneedsfourlegs',
      UserId: datacache.users.bjoernOwasp.id
    }).catch((err: unknown) => {
      logger.error(`Could not create memory: ${utils.getErrorMessage(err)}`)
    }),
    ...utils.thaw(config.get('memories')).map(async (memory: Memory) => {
      let tmpImageFileName = memory.image
      if (utils.isUrl(memory.image)) {
        const imageUrl = memory.image
        tmpImageFileName = utils.extractFilename(memory.image)
        void utils.downloadToFile(imageUrl, 'frontend/dist/frontend/assets/public/images/uploads/' + tmpImageFileName)
      }
      if (memory.geoStalkingMetaSecurityQuestion && memory.geoStalkingMetaSecurityAnswer) {
        await createSecurityAnswer(datacache.users.john.id, memory.geoStalkingMetaSecurityQuestion, memory.geoStalkingMetaSecurityAnswer)
        memory.user = 'john'
      }
      if (memory.geoStalkingVisualSecurityQuestion && memory.geoStalkingVisualSecurityAnswer) {
        await createSecurityAnswer(datacache.users.emma.id, memory.geoStalkingVisualSecurityQuestion, memory.geoStalkingVisualSecurityAnswer)
        memory.user = 'emma'
      }
      return await MemoryModel.create({
        imagePath: 'assets/public/images/uploads/' + tmpImageFileName,
        caption: memory.caption,
        UserId: datacache.users[memory.user].id
      }).catch((err: unknown) => {
        logger.error(`Could not create memory: ${utils.getErrorMessage(err)}`)
      })
    })
  ]

  return await Promise.all(memories)
}

async function createProducts () {
  const products = utils.thaw(config.get('products')).map((product: Product) => {
    product.price = product.price ?? Math.floor(Math.random() * 9 + 1)
    product.deluxePrice = product.deluxePrice ?? product.price
    product.description = product.description || 'Lorem ipsum dolor sit amet, consectetuer adipiscing elit.'

    // set default image values
    product.image = product.image ?? 'undefined.png'
    if (utils.isUrl(product.image)) {
      const imageUrl = product.image
      product.image = utils.extractFilename(product.image)
      void utils.downloadToFile(imageUrl, 'frontend/dist/frontend/assets/public/images/products/' + product.image)
    }
    return product
  })

  // add Challenge specific information
  const christmasChallengeProduct = products.find(({ useForChristmasSpecialChallenge }: { useForChristmasSpecialChallenge: boolean }) => useForChristmasSpecialChallenge)
  const pastebinLeakChallengeProduct = products.find(({ keywordsForPastebinDataLeakChallenge }: { keywordsForPastebinDataLeakChallenge: string[] }) => keywordsForPastebinDataLeakChallenge)
  const tamperingChallengeProduct = products.find(({ urlForProductTamperingChallenge }: { urlForProductTamperingChallenge: string }) => urlForProductTamperingChallenge)
  const blueprintRetrievalChallengeProduct = products.find(({ fileForRetrieveBlueprintChallenge }: { fileForRetrieveBlueprintChallenge: string }) => fileForRetrieveBlueprintChallenge)

  christmasChallengeProduct.description += ' (Seasonal special offer! Limited availability!)'
  christmasChallengeProduct.deletedDate = '2014-12-27 00:00:00.000 +00:00'
  tamperingChallengeProduct.description += ' <a href="' + tamperingChallengeProduct.urlForProductTamperingChallenge + '" target="_blank">More...</a>'
  tamperingChallengeProduct.deletedDate = null
  pastebinLeakChallengeProduct.description += ' (This product is unsafe! We plan to remove it from the stock!)'
  pastebinLeakChallengeProduct.deletedDate = '2019-02-1 00:00:00.000 +00:00'

  let blueprint = blueprintRetrievalChallengeProduct.fileForRetrieveBlueprintChallenge
  if (utils.isUrl(blueprint)) {
    const blueprintUrl = blueprint
    blueprint = utils.extractFilename(blueprint)
    await utils.downloadToFile(blueprintUrl, 'frontend/dist/frontend/assets/public/images/products/' + blueprint)
  }
  datacache.retrieveBlueprintChallengeFile = blueprint

  return await Promise.all(
    products.map(
      async ({ reviews = [], useForChristmasSpecialChallenge = false, urlForProductTamperingChallenge = false, fileForRetrieveBlueprintChallenge = false, deletedDate = false, ...product }) =>
        await ProductModel.create({
          name: product.name,
          description: product.description,
          price: product.price,
          deluxePrice: product.deluxePrice,
          image: product.image
        }).catch(
          (err: unknown) => {
            logger.error(`Could not insert Product ${product.name}: ${utils.getErrorMessage(err)}`)
          }
        ).then((persistedProduct) => {
          if (persistedProduct) {
            if (useForChristmasSpecialChallenge) { datacache.products.christmasSpecial = persistedProduct }
            if (urlForProductTamperingChallenge) {
              datacache.products.osaft = persistedProduct
              datacache.challenges.changeProductChallenge.update({
                description: customizeChangeProductChallenge(
                  datacache.challenges.changeProductChallenge.description,
                  config.get('challenges.overwriteUrlForProductTamperingChallenge'),
                  persistedProduct)
              })
            }
            if (fileForRetrieveBlueprintChallenge && datacache.challenges.changeProductChallenge.hint) {
              datacache.challenges.retrieveBlueprintChallenge.update({
                hint: customizeRetrieveBlueprintChallenge(
                  datacache.challenges.retrieveBlueprintChallenge.hint,
                  persistedProduct)
              })
            }
            if (deletedDate) void deleteProduct(persistedProduct.id) // TODO Rename into "isDeleted" or "deletedFlag" in config for v14.x release
          } else {
            throw new Error('No persisted product found!')
          }
          return persistedProduct
        })
          .then(async ({ id }: { id: number }) =>
            await Promise.all(
              reviews.map(({ text, author }) =>
                mongodb.reviews.insert({
                  message: text,
                  author: datacache.users[author].email,
                  product: id,
                  likesCount: 0,
                  likedBy: []
                }).catch((err: unknown) => {
                  logger.error(`Could not insert Product Review ${text}: ${utils.getErrorMessage(err)}`)
                })
              )
            )
          )
    )
  )

  function customizeChangeProductChallenge (description: string, customUrl: string, customProduct: Product) {
    let customDescription = description.replace(/OWASP SSL Advanced Forensic Tool \(O-Saft\)/g, customProduct.name)
    customDescription = customDescription.replace('https://owasp.slack.com', customUrl)
    return customDescription
  }

  function customizeRetrieveBlueprintChallenge (hint: string, customProduct: Product) {
    return hint.replace(/OWASP Juice Shop Logo \(3D-printed\)/g, customProduct.name)
  }
}

async function createBaskets () {
  const baskets = [
    { UserId: 1 },
    { UserId: 2 },
    { UserId: 3 },
    { UserId: 11 },
    { UserId: 16 }
  ]

  return await Promise.all(
    baskets.map(async basket => {
      return await BasketModel.create({
        UserId: basket.UserId
      }).catch((err: unknown) => {
        logger.error(`Could not insert Basket for UserId ${basket.UserId}: ${utils.getErrorMessage(err)}`)
      })
    })
  )
}

async function createBasketItems () {
  const basketItems = [
    {
      BasketId: 1,
      ProductId: 1,
      quantity: 2
    },
    {
      BasketId: 1,
      ProductId: 2,
      quantity: 3
    },
    {
      BasketId: 1,
      ProductId: 3,
      quantity: 1
    },
    {
      BasketId: 2,
      ProductId: 4,
      quantity: 2
    },
    {
      BasketId: 3,
      ProductId: 4,
      quantity: 1
    },
    {
      BasketId: 4,
      ProductId: 4,
      quantity: 2
    },
    {
      BasketId: 5,
      ProductId: 3,
      quantity: 5
    },
    {
      BasketId: 5,
      ProductId: 4,
      quantity: 2
    }
  ]

  return await Promise.all(
    basketItems.map(async basketItem => {
      return await BasketItemModel.create(basketItem).catch((err: unknown) => {
        logger.error(`Could not insert BasketItem for BasketId ${basketItem.BasketId}: ${utils.getErrorMessage(err)}`)
      })
    })
  )
}

async function createAnonymousFeedback () {
  const feedbacks = [
    {
      comment: 'Incompetent customer support! Can\'t even upload photo of broken purchase!<br><em>Support Team: Sorry, only order confirmation PDFs can be attached to complaints!</em>',
      rating: 2
    },
    {
      comment: 'This is <b>the</b> store for awesome stuff of all kinds!',
      rating: 4
    },
    {
      comment: 'Never gonna buy anywhere else from now on! Thanks for the great service!',
      rating: 4
    },
    {
      comment: 'Keep up the good work!',
      rating: 3
    }
  ]

  return await Promise.all(
    feedbacks.map(async (feedback) => await createFeedback(null, feedback.comment, feedback.rating))
  )
}

async function createFeedback (UserId: number | null, comment: string, rating: number, author?: string) {
  const authoredComment = author ? `${comment} (***${author.slice(3)})` : `${comment} (anonymous)`
  return await FeedbackModel.create({ UserId, comment: authoredComment, rating }).catch((err: unknown) => {
    logger.error(`Could not insert Feedback ${authoredComment} mapped to UserId ${UserId}: ${utils.getErrorMessage(err)}`)
  })
}

async function createComplaints () {
  return await ComplaintModel.create({
    UserId: 3,
    message: 'I\'ll build my own eCommerce business! With Black Jack! And Hookers!'
  }).catch((err: unknown) => {
    logger.error(`Could not insert Complaint: ${utils.getErrorMessage(err)}`)
  })
}

async function createRecycleItem () {
  const recycles = [
    {
      UserId: 2,
      quantity: 800,
      AddressId: 4,
      date: '2270-01-17',
      isPickup: true
    },
    {
      UserId: 3,
      quantity: 1320,
      AddressId: 6,
      date: '2006-01-14',
      isPickup: true
    },
    {
      UserId: 4,
      quantity: 120,
      AddressId: 1,
      date: '2018-04-16',
      isPickup: true
    },
    {
      UserId: 1,
      quantity: 300,
      AddressId: 3,
      date: '2018-01-17',
      isPickup: true
    },
    {
      UserId: 4,
      quantity: 350,
      AddressId: 1,
      date: '2018-03-17',
      isPickup: true
    },
    {
      UserId: 3,
      quantity: 200,
      AddressId: 6,
      date: '2018-07-17',
      isPickup: true
    },
    {
      UserId: 4,
      quantity: 140,
      AddressId: 1,
      date: '2018-03-19',
      isPickup: true
    },
    {
      UserId: 1,
      quantity: 150,
      AddressId: 3,
      date: '2018-05-12',
      isPickup: true
    },
    {
      UserId: 16,
      quantity: 500,
      AddressId: 2,
      date: '2019-02-18',
      isPickup: true
    }
  ]
  return await Promise.all(
    recycles.map(async (recycle) => await createRecycle(recycle))
  )
}

async function createRecycle (data: { UserId: number, quantity: number, AddressId: number, date: string, isPickup: boolean }) {
  return await RecycleModel.create({
    UserId: data.UserId,
    AddressId: data.AddressId,
    quantity: data.quantity,
    isPickup: data.isPickup,
    date: data.date
  }).catch((err: unknown) => {
    logger.error(`Could not insert Recycling Model: ${utils.getErrorMessage(err)}`)
  })
}

async function createSecurityQuestions () {
  const questions = await loadStaticData('securityQuestions')

  await Promise.all(
    questions.map(async ({ question }: SecurityQuestion) => {
      try {
        await SecurityQuestionModel.create({ question })
      } catch (err) {
        logger.error(`Could not insert SecurityQuestion ${question}: ${utils.getErrorMessage(err)}`)
      }
    })
  )
}

async function createSecurityAnswer (UserId: number, SecurityQuestionId: number, answer: string) {
  return await SecurityAnswerModel.create({ SecurityQuestionId, UserId, answer }).catch((err: unknown) => {
    logger.error(`Could not insert SecurityAnswer ${answer} mapped to UserId ${UserId}: ${utils.getErrorMessage(err)}`)
  })
}

async function createOrders () {
  const products = config.get<Product[]>('products')
  const basket1Products = [
    {
      quantity: 3,
      id: products[0].id,
      name: products[0].name,
      price: products[0].price,
      total: products[0].price * 3,
      bonus: Math.round(products[0].price / 10) * 3
    },
    {
      quantity: 1,
      id: products[1].id,
      name: products[1].name,
      price: products[1].price,
      total: products[1].price * 1,
      bonus: Math.round(products[1].price / 10) * 1
    }
  ]

  const basket2Products = [
    {
      quantity: 3,
      id: products[2].id,
      name: products[2].name,
      price: products[2].price,
      total: products[2].price * 3,
      bonus: Math.round(products[2].price / 10) * 3
    }
  ]

  const basket3Products = [
    {
      quantity: 3,
      id: products[0].id,
      name: products[0].name,
      price: products[0].price,
      total: products[0].price * 3,
      bonus: Math.round(products[0].price / 10) * 3
    },
    {
      quantity: 5,
      id: products[3].id,
      name: products[3].name,
      price: products[3].price,
      total: products[3].price * 5,
      bonus: Math.round(products[3].price / 10) * 5
    }
  ]

  const adminEmail = 'admin@' + config.get('application.domain')
  const orders = [
    {
      orderId: security.hash(adminEmail).slice(0, 4) + '-' + utils.randomHexString(16),
      email: (adminEmail.replace(/[aeiou]/gi, '*')),
      totalPrice: basket1Products[0].total + basket1Products[1].total,
      bonus: basket1Products[0].bonus + basket1Products[1].bonus,
      products: basket1Products,
      eta: Math.floor((Math.random() * 5) + 1).toString(),
      delivered: false
    },
    {
      orderId: security.hash(adminEmail).slice(0, 4) + '-' + utils.randomHexString(16),
      email: (adminEmail.replace(/[aeiou]/gi, '*')),
      totalPrice: basket2Products[0].total,
      bonus: basket2Products[0].bonus,
      products: basket2Products,
      eta: '0',
      delivered: true
    },
    {
      orderId: security.hash('demo').slice(0, 4) + '-' + utils.randomHexString(16),
      email: 'd*m*',
      totalPrice: basket3Products[0].total + basket3Products[1].total,
      bonus: basket3Products[0].bonus + basket3Products[1].bonus,
      products: basket3Products,
      eta: '0',
      delivered: true
    }
  ]

  return await Promise.all(
    orders.map(({ orderId, email, totalPrice, bonus, products, eta, delivered }) =>
      mongodb.orders.insert({
        orderId: orderId,
        email: email,
        totalPrice: totalPrice,
        bonus: bonus,
        products: products,
        eta: eta,
        delivered: delivered
      }).catch((err: unknown) => {
        logger.error(`Could not insert Order ${orderId}: ${utils.getErrorMessage(err)}`)
      })
    )
  )
}
