// @flow
/* eslint-disable no-extra-boolean-cast */

import * as middy from "middy";
import * as Joi from "joi";
import { indexOf } from "lodash";

export type IBodyConfig = {
  schema: Joi.JoiObject
};

export type IRequestValidatorConfig = {
  restrictedAccess: boolean,
  permittedSource: string[],
  body?: IBodyConfig
};

export const requestValidator = (
  config: IRequestValidatorConfig
): middy.IMiddyMiddlewareObject => {
  return {
    before: (handler, next) => {
      if (config.restrictedAccess && !handler.event.requestContext.authorizer) {
        console.error(handler.event);
        return handler.callback(null, {
          statusCode: 401
        });
      }

      if (config.permittedSource) {
        const source: string =
          handler.event.headers && handler.event.headers.Source
            ? handler.event.headers.Source
            : "app";

        if (indexOf(config.permittedSource, source) === -1) {
          console.error(source);
          return handler.callback(null, {
            statusCode: 403
          });
        }

        let userGroups: any =
          handler.event.requestContext.authorizer.claims["cognito:groups"];

        if (userGroups) {
          if (userGroups === "admin") {
            userGroups = ["admin"];
          }

          if (
            source === "backoffice" &&
            (!userGroups || (userGroups && indexOf(userGroups, "admin") === -1))
          ) {
            console.error(userGroups);
            console.error(source);
            return handler.callback(null, {
              statusCode: 403
            });
          }
        }
      }

      if (!!config.body?.schema) {
        if (!handler.event.body) {
          return handler.callback(null, {
            statusCode: 400,
            body: JSON.stringify({ error: "Body is required" })
          });
        }

        const validation = Joi.validate(
          handler.event.body,
          config.body?.schema,
          {
            abortEarly: false
          }
        );
        console.log(validation);
        if (validation.error) {
          console.error(validation);
          return handler.callback(null, {
            statusCode: 400,
            body: JSON.stringify({ error: validation })
          });
        }
      }

      return next();
    }
  };
};
