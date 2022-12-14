import "reflect-metadata";
import { ShippingProfile } from "../../../..";
import { DeleteResponse } from "../../../../types/common";
declare const _default: (app: any) => any;
export default _default;
export declare const defaultAdminShippingProfilesFields: (keyof ShippingProfile)[];
export declare type AdminDeleteShippingProfileRes = DeleteResponse;
export declare const defaultAdminShippingProfilesRelations: (keyof ShippingProfile)[];
export declare type AdminShippingProfilesRes = {
    shipping_profile: ShippingProfile;
};
export declare type AdminShippingProfilesListRes = {
    shipping_profiles: ShippingProfile[];
};
export * from "./create-shipping-profile";
export * from "./delete-shipping-profile";
export * from "./update-shipping-profile";
