import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify, decode } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
import Axios from 'axios'
import { Jwt } from '../../auth/Jwt'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
const jwksUrl = 'https://dev-h72ydfr71scohpq6.us.auth0.com/.well-known/jwks.json'

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)
  // logger.info(`token: ${token}`);
  const jwt: Jwt = decode(token, { complete: true }) as Jwt
  // logger.info(`jwt: ${jwt}`);

  const res = await Axios.get(jwksUrl);
  // logger.info(`res: ${res}`);
  const keys = res.data.keys;
  // logger.info(`keys: ${keys}`);
  // logger.info(`jwt.header.kid: ${jwt.header.kid}`);
  const signingKey = keys.find(key => key.kid === jwt.header.kid);
  // logger.info(`signingKey: ${signingKey}`);

  if (!signingKey) {
    throw new Error(`Unable to find a signing key that matches '${jwt.header.kid}'`);
  }

  const pemData = signingKey.x5c[0];

  const cert = createCert(pemData)

  const verifiedToken = verify(token, cert, {
    algorithms: ['RS256']
  }) as JwtPayload;
  logger.info('verifiedToken: ', verifiedToken);

  return verifiedToken;
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}

function createCert(pemData) {
  // var cert = pemData.match(/.{1,64}/g).join('\n');
  const cert = `-----BEGIN CERTIFICATE-----\n${pemData}\n-----END CERTIFICATE-----\n`;
  return cert;
}