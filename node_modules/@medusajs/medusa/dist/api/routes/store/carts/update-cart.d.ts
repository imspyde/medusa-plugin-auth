import { AddressPayload } from "../../../../types/common";
/**
 * @oas [post] /carts/{id}
 * operationId: PostCartsCart
 * summary: Update a Cart
 * description: "Updates a Cart."
 * parameters:
 *   - (path) id=* {string} The id of the Cart.
 * requestBody:
 *   content:
 *     application/json:
 *       schema:
 *         properties:
 *           region_id:
 *             type: string
 *             description: The id of the Region to create the Cart in.
 *           country_code:
 *             type: string
 *             description: "The 2 character ISO country code to create the Cart in."
 *             externalDocs:
 *               url: https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#Officially_assigned_code_elements
 *               description: See a list of codes.
 *           email:
 *             type: string
 *             description: "An email to be used on the Cart."
 *             format: email
 *           sales_channel_id:
 *             type: string
 *             description: The ID of the Sales channel to update the Cart with.
 *           billing_address:
 *             description: "The Address to be used for billing purposes."
 *             anyOf:
 *               - $ref: "#/components/schemas/address"
 *                 description: A full billing address object.
 *               - type: string
 *                 description: The billing address ID
 *           shipping_address:
 *             description: "The Address to be used for shipping."
 *             anyOf:
 *               - $ref: "#/components/schemas/address"
 *                 description: A full shipping address object.
 *               - type: string
 *                 description: The shipping address ID
 *           gift_cards:
 *             description: "An array of Gift Card codes to add to the Cart."
 *             type: array
 *             items:
 *               required:
 *                 - code
 *               properties:
 *                 code:
 *                   description: "The code that a Gift Card is identified by."
 *                   type: string
 *           discounts:
 *             description: "An array of Discount codes to add to the Cart."
 *             type: array
 *             items:
 *               required:
 *                 - code
 *               properties:
 *                 code:
 *                   description: "The code that a Discount is identifed by."
 *                   type: string
 *           customer_id:
 *             description: "The ID of the Customer to associate the Cart with."
 *             type: string
 *           context:
 *             description: "An optional object to provide context to the Cart."
 *             type: object
 *             example:
 *               ip: "::1"
 *               user_agent: "Chrome"
 * x-codeSamples:
 *   - lang: JavaScript
 *     label: JS Client
 *     source: |
 *       import Medusa from "@medusajs/medusa-js"
 *       const medusa = new Medusa({ baseUrl: MEDUSA_BACKEND_URL, maxRetries: 3 })
 *       medusa.carts.update(cart_id, {
 *         email: 'user@example.com'
 *       })
 *       .then(({ cart }) => {
 *         console.log(cart.id);
 *       });
 *   - lang: Shell
 *     label: cURL
 *     source: |
 *       curl --location --request POST 'https://medusa-url.com/store/carts/{id}' \
 *       --header 'Content-Type: application/json' \
 *       --data-raw '{
 *           "email": "user@example.com"
 *       }'
 * tags:
 *   - Cart
 * responses:
 *   200:
 *     description: OK
 *     content:
 *       application/json:
 *         schema:
 *           properties:
 *             cart:
 *               $ref: "#/components/schemas/cart"
 *   "400":
 *     $ref: "#/components/responses/400_error"
 *   "404":
 *     $ref: "#/components/responses/not_found_error"
 *   "409":
 *     $ref: "#/components/responses/invalid_state_error"
 *   "422":
 *     $ref: "#/components/responses/invalid_request_error"
 *   "500":
 *     $ref: "#/components/responses/500_error"
 */
declare const _default: (req: any, res: any) => Promise<void>;
export default _default;
declare class GiftCard {
    code: string;
}
declare class Discount {
    code: string;
}
export declare class StorePostCartsCartReq {
    region_id?: string;
    country_code?: string;
    email?: string;
    billing_address?: AddressPayload | string;
    shipping_address?: AddressPayload | string;
    gift_cards?: GiftCard[];
    discounts?: Discount[];
    customer_id?: string;
    context?: object;
    sales_channel_id?: string;
}
