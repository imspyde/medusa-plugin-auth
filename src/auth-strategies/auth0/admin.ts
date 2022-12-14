import passport from 'passport';
import { Strategy as Auth0Strategy } from 'passport-auth0';
import { ConfigModule, MedusaContainer } from '@medusajs/medusa/dist/types/global';
import { AUTH_PROVIDER_KEY, TWENTY_FOUR_HOURS_IN_MS } from '../../types';
import { UserService } from '@medusajs/medusa';
import { MedusaError } from 'medusa-core-utils';
import { Router } from 'express';
import cors from 'cors';
import { buildCallbackHandler } from '../../core/utils/build-callback-handler';
import { PassportStrategy } from '../../core/Strategy';
import { Auth0Options, AUTH0_ADMIN_STRATEGY_NAME, ExtraParams, Profile } from './types';

export class Auth0AdminStrategy extends PassportStrategy(Auth0Strategy, AUTH0_ADMIN_STRATEGY_NAME) {
	constructor(
		protected readonly container: MedusaContainer,
		protected readonly configModule: ConfigModule,
		protected readonly strategyOptions: Auth0Options
	) {
		super({
			domain: strategyOptions.auth0Domain,
			clientID: strategyOptions.clientID,
			clientSecret: strategyOptions.clientSecret,
			callbackURL: strategyOptions.admin.callbackUrl,
			passReqToCallback: true,
			state: true,
		});
	}

	async validate(
		req: Request,
		accessToken: string,
		refreshToken: string,
		extraParams: ExtraParams,
		profile: Profile
	): Promise<null | { id: string }> {
		if (this.strategyOptions.admin.verifyCallback) {
			return await this.strategyOptions.admin.verifyCallback(
				this.container,
				req,
				accessToken,
				refreshToken,
				extraParams,
				profile
			);
		}
		return await this.defaultValidate(profile);
	}

	private async defaultValidate(profile: Profile): Promise<{ id: string } | never> {
		const userService: UserService = this.container.resolve('userService');
		const email = profile.emails?.[0]?.value;

		if (!email) {
			throw new MedusaError(
				MedusaError.Types.NOT_ALLOWED,
				`Your Auth0 account does not contain a valid email and cannot be used`
			);
		}

		const user = await userService.retrieveByEmail(email).catch(() => void 0);

		if (user) {
			if (!user.metadata || user.metadata[AUTH_PROVIDER_KEY] !== AUTH0_ADMIN_STRATEGY_NAME) {
				throw new MedusaError(MedusaError.Types.INVALID_DATA, `Admin with email ${email} already exists`);
			}
		} else {
			throw new MedusaError(
				MedusaError.Types.NOT_ALLOWED,
				`Unable to authenticate the user with the email ${email}`
			);
		}

		return { id: user.id };
	}
}

/**
 * Return the router that holds the auth0 admin authentication routes
 * @param auth0
 * @param configModule
 */
export function getAuth0AdminAuthRouter(auth0: Auth0Options, configModule: ConfigModule): Router {
	const router = Router();

	const adminCorsOptions = {
		origin: configModule.projectConfig.admin_cors.split(','),
		credentials: true,
	};

	const authPath = auth0.admin.authPath ?? '/admin/auth/auth0';

	router.get(authPath, cors(adminCorsOptions));
	router.get(
		authPath,
		passport.authenticate(AUTH0_ADMIN_STRATEGY_NAME, {
			scope: 'openid email profile',
			session: false,
		})
	);

	const expiresIn = auth0.admin.expiresIn ?? TWENTY_FOUR_HOURS_IN_MS;
	const callbackHandler = buildCallbackHandler(
		'admin',
        configModule.projectConfig.jwt_secret,
		expiresIn,
		auth0.admin.successRedirect
	);

	const authPathCb = auth0.admin.authCallbackPath ?? '/admin/auth/auth0/cb';

	router.get(authPathCb, cors(adminCorsOptions));
	router.get(
		authPathCb,
		(req, res, next) => {
			if (req.user) {
				callbackHandler(req, res);
			}

			next();
		},
		passport.authenticate(AUTH0_ADMIN_STRATEGY_NAME, {
			failureRedirect: auth0.admin.failureRedirect,
			session: false,
		}),
		callbackHandler
	);

	return router;
}