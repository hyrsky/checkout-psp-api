import CheckoutApi, { CheckoutAlgorithm } from '../src/'
import * as request from 'request-promise-native'

jest.mock('request-promise-native')

const mockedRequest = request as jest.Mocked<typeof request>

describe('Test checkout api', () => {
  const CHECKOUT_MERCHANT_ID = '375917'
  const CHECKOUT_SECRET = 'SAIPPUAKAUPPIAS'
  const checkoutAPI = new CheckoutApi(
    CHECKOUT_MERCHANT_ID,
    CHECKOUT_SECRET,
    'sha256'
  )

  afterEach(() => {
    // jest.clearAllMocks()
  })

  it('Should calculate hmac', () => {
    // Magic values from:
    // https://checkoutfinland.github.io/psp-api/#/examples?id=hmac-calculation-node-js
    const signature =
      '3708f6497ae7cc55a2e6009fc90aa10c3ad0ef125260ee91b19168750f6d74f6'
    const headers = {
      'checkout-account': '375917',
      'checkout-algorithm': 'sha256',
      'checkout-method': 'POST',
      'checkout-nonce': '564635208570151',
      'checkout-timestamp': '2018-07-06T10:01:31.904Z'
    }
    const body = JSON.stringify({
      stamp: 'unique-identifier-for-merchant',
      reference: '3759170',
      amount: 1525,
      currency: 'EUR',
      language: 'FI',
      items: [
        {
          unitPrice: 1525,
          units: 1,
          vatPercentage: 24,
          productCode: '#1234',
          deliveryDate: '2018-09-01'
        }
      ],
      customer: {
        email: 'test.customer@example.com'
      },
      redirectUrls: {
        success: 'https://ecom.example.com/cart/success',
        cancel: 'https://ecom.example.com/cart/cancel'
      }
    })

    expect(
      CheckoutApi.calcMac('SAIPPUAKAUPPIAS', 'sha256', headers, body)
    ).toEqual(signature)
  })

  it('Should validate signature algorithm', () => {
    const invalidAlgorithm: CheckoutAlgorithm = 'md5' as any
    const headers = {
      'checkout-account': '375917',
      'checkout-algorithm': 'md5',
      'checkout-method': 'POST',
      signature: ''
    }

    // md5 should not be accepted
    headers.signature = CheckoutApi.calcMac(
      CHECKOUT_SECRET,
      invalidAlgorithm,
      headers,
      ''
    )

    expect(
      () => new CheckoutApi('account-id', 'secret', invalidAlgorithm)
    ).toThrowError()
    expect(() => checkoutAPI.validateResponse(headers)).toThrowError()
  })

  it('Should validate response hmac', async () => {
    const body = '{}'
    const headers = {
      'checkout-account': '375917',
      'checkout-algorithm': 'sha256',
      'checkout-method': 'POST',
      signature: ''
    }

    headers.signature = CheckoutApi.calcMac(
      CHECKOUT_SECRET,
      checkoutAPI.algorithm,
      headers,
      body
    )

    const response = {
      headers: headers,
      body: body
    }

    mockedRequest.post
      // Valid signature should pass
      .mockResolvedValueOnce(response)
      // Invalid signature should fail
      .mockResolvedValueOnce({
        ...response,
        headers: { ...headers, signature: 'invalid-signature' }
      })

    await expect(
      checkoutAPI.sendRequest('POST', '/', {}, '{}')
    ).resolves.toBeTruthy()
    await expect(
      checkoutAPI.sendRequest('POST', '/', {}, '{}')
    ).rejects.toBeTruthy()

    // All mocks should be consumed.
    expect(mockedRequest.post).toBeCalledTimes(2)
  })

  it('Should validate hmac', () => {
    // Magic parameters from real checkout request with test api credentials.
    const result = checkoutAPI.validateResponse({
      'checkout-account': '375917',
      'checkout-algorithm': 'sha512',
      'checkout-amount': '5000',
      'checkout-provider': 'creditcard',
      'checkout-reference': '1012',
      'checkout-stamp': '0a2ece27-aa4f-4cea-920c-16b8574ad7a1',
      'checkout-status': 'fail',
      'checkout-transaction-id': '41ae943e-24f6-11e9-9fcc-2b299b6a1076',
      signature:
        'e2f1d0d4908a933d695abb278c67313c2f7609670f4744536709a10a599d343e' +
        '0b0339800b937ee66403ca40fab4f347cd774b62c163268d0b14521248d9875c'
    })

    expect(result).toEqual(true)
  })

  it('Test createPayment()', async () => {
    const myCheckoutAPI = new CheckoutApi(CHECKOUT_MERCHANT_ID, CHECKOUT_SECRET)

    // Function that makes the actual http request.
    myCheckoutAPI.sendRequest = jest.fn().mockResolvedValueOnce('response')

    const request = myCheckoutAPI.createPayment({
      stamp: 'unique-identifier-for-merchant',
      reference: '3759170',
      amount: 1525,
      currency: 'EUR',
      language: 'FI',
      items: [
        {
          unitPrice: 1525,
          units: 1,
          vatPercentage: 24,
          productCode: '#1234',
          deliveryDate: '2018-09-01'
        }
      ],
      customer: {
        email: 'test.customer@example.com'
      },
      redirectUrls: {
        success: 'https://ecom.example.com/cart/success',
        cancel: 'https://ecom.example.com/cart/cancel'
      }
    })

    await expect(request).resolves.toEqual('response')

    expect(myCheckoutAPI.sendRequest).toHaveBeenCalled()
  })
})
