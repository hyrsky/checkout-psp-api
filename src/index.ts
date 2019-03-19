import * as crypto from 'crypto'
import * as request from 'request-promise-native'
import { v4 as uuid } from 'uuid'

const CHECKOUT_ENDPOINT = 'https://api.checkout.fi'

type Dictionary<T> = { [key: string]: T }

export interface CheckoutItem {
  /** Price per unit, VAT included, in each country's minor unit, e.g. for Euros use cents */
  unitPrice: number
  /** Quantity, how many items ordered */
  units: number
  /** VAT percentage */
  vatPercentage: number
  /** Merchant product code. May appear on invoices of certain payment methods. */
  productCode: string
  /** When is this item going to be delivered */
  deliveryDate: string
  /** Item description. May appear on invoices of certain payment methods. */
  description?: string
  /** Merchant specific item category */
  category?: string
  /** Unique identifier for this item. Required for Shop-in-Shop payments. */
  stamp?: string
  /** Reference for this item. Required for Shop-in-Shop payments. */
  reference?: string
  /** Merchant ID for the item. Required for Shop-in-Shop payments, do not use for normal payments. */
  merchant?: string
  /** Shop-in-Shop commission. Do not use for normal payments. */
  commission?: CheckoutComission
}

export interface CheckoutComission {
  /** Merchant who gets the commission */
  merchant: string
  /** Amount of commission in currency's minor units, eg. for Euros use cents. VAT not applicable. */
  amount: number
}

export interface CheckoutCustomer {
  /** Email */
  email: string
  /** First name */
  firstName?: string
  /** Last name */
  lastName?: string
  /** Phone number */
  phoneNumber?: string
  /** VAT ID, if any */
  vatId?: string
}

export interface CheckoutAddress {
  /** Street address */
  streetAddress: string
  /** Postal code */
  postalCode: string
  /** City */
  city: string
  /** County/State */
  county: string
  /** Alpha-2 country code */
  country: string
}

export interface CheckoutCallback {
  /** Called on successful payment */
  success: string
  /** Called on cancelled payment */
  cancel: string
}

export interface CheckoutPaymentOptions {
  /** Merchant unique identifier for the order */
  stamp: string
  /** Order reference */
  reference: string
  /**
   * Total amount of the payment in currency's minor units, eg. for Euros use cents.
   * Must match the total sum of items.
   */
  amount: number
  /** Currency, only EUR supported at the moment */
  currency: 'EUR'
  /** Payment's language, currently supported are FI, SV, and EN */
  language: 'FI' | 'SV' | 'EN'
  /** Array of items */
  items: CheckoutItem[]
  /** Cusomer information */
  customer: CheckoutCustomer
  /** Delivery address */
  deliveryAddress?: CheckoutAddress
  /** Invoicing address */
  invoicingAddress?: CheckoutAddress
  /** Where to redirect browser after a payment is paid or cancelled */
  redirectUrls: CheckoutCallback
  /** Which url to ping after this payment is paid or cancelled */
  callbackUrls?: CheckoutCallback
}

export interface CheckoutPayment {
  transactionId: string
  href: string
  /** Available payment methods. */
  providers: CheckoutProvider[]
}

export interface CheckoutProvider {
  url: string
  icon: string
  svg: string
  name: string
  group: string
  id: string
  parameters: CheckoutProviderParameter[]
}

export interface CheckoutProviderParameter {
  name: string
  value: string
}

// Helper type https://stackoverflow.com/a/45257357
const Tuple = <T extends string[]>(...args: T) => args

// List of hashing algoritms supported by checkout.
const SupportedAlgorithms = Tuple('sha256', 'sha512')

export type CheckoutAlgorithm = typeof SupportedAlgorithms[number]

export function isSupportedAlgorithm(
  algorithm: string
): algorithm is CheckoutAlgorithm {
  return SupportedAlgorithms.includes(algorithm as CheckoutAlgorithm)
}

export default class CheckoutApi {
  private readonly merchantId: string
  private readonly secret: string
  algorithm: CheckoutAlgorithm

  constructor(
    merchantId: string,
    secret: string,
    algorithm: CheckoutAlgorithm = 'sha512'
  ) {
    this.merchantId = merchantId
    this.secret = secret

    if (!isSupportedAlgorithm(algorithm)) {
      throw new Error(`${algorithm} is not supported signature algorithm`)
    }

    this.algorithm = algorithm
  }

  static calcMac(
    secret: string,
    algorithm: CheckoutAlgorithm,
    params: Dictionary<string>,
    body?: string
  ): string {
    const hmacPayload = Object.keys(params)
      .filter(item => item.startsWith('checkout-'))
      .sort()
      .map(key => `${key}:${params[key]}`)
      .concat(body || '')
      .join('\n')

    return crypto
      .createHmac(algorithm, secret)
      .update(hmacPayload)
      .digest('hex')
  }

  validateResponse(
    { signature, ...params }: Dictionary<string>,
    body?: string
  ): boolean {
    // Pull signature algorithm from params.
    const algorithm = params['checkout-algorithm']

    // Check that response is hashed with secure algorithm.
    if (!isSupportedAlgorithm(algorithm)) {
      throw new Error(`${algorithm} is not supported signature algorithm`)
    }

    // Check signature.
    return (
      signature === CheckoutApi.calcMac(this.secret, algorithm, params, body)
    )
  }

  createPayment(data: CheckoutPaymentOptions): Promise<CheckoutPayment> {
    return this.sendRequest(
      'POST',
      `/payments`,
      this.makeHeaders('POST'),
      JSON.stringify(data)
    )
  }

  sendRequest(
    method: string,
    url: string,
    headers: Dictionary<string>,
    body?: string
  ): Promise<any> {
    // Add signature header.
    headers.signature = CheckoutApi.calcMac(
      this.secret,
      this.algorithm,
      headers,
      body
    )
    headers['Content-Type'] = 'application/json; charset=utf-8'

    return request
      .post({
        url: CHECKOUT_ENDPOINT + url,
        resolveWithFullResponse: true, // Need headers for response verification
        method,
        headers,
        body
      })
      .then(response => {
        if (!this.validateResponse(response.headers, response.body)) {
          throw new Error('Signature verification failed')
        }

        return JSON.parse(response.body)
      })
  }

  private makeHeaders(method: string): Dictionary<string> {
    return {
      'checkout-account': this.merchantId,
      'checkout-algorithm': this.algorithm,
      'checkout-method': method,
      'checkout-nonce': uuid(),
      'checkout-timestamp': new Date().toISOString()
    }
  }
}
