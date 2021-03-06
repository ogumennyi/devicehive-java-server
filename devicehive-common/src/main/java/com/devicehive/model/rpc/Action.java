package com.devicehive.model.rpc;

/*
 * #%L
 * DeviceHive Common Module
 * %%
 * Copyright (C) 2016 DataArt
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

public enum Action {
    ERROR_RESPONSE,

    NOTIFICATION_SEARCH_REQUEST,
    NOTIFICATION_SEARCH_RESPONSE,
    NOTIFICATION_INSERT_REQUEST,
    NOTIFICATION_INSERT_RESPONSE,
    NOTIFICATION_SUBSCRIBE_REQUEST,
    NOTIFICATION_SUBSCRIBE_RESPONSE,
    NOTIFICATION_UNSUBSCRIBE_REQUEST,
    NOTIFICATION_UNSUBSCRIBE_RESPONSE,
    NOTIFICATION_EVENT,

    COMMAND_SEARCH_REQUEST,
    COMMAND_SEARCH_RESPONSE,
    COMMAND_INSERT_REQUEST,
    COMMAND_INSERT_RESPONSE,
    COMMAND_UPDATE_REQUEST,
    COMMAND_SUBSCRIBE_REQUEST,
    COMMAND_SUBSCRIBE_RESPONSE,
    COMMAND_UNSUBSCRIBE_REQUEST,
    COMMAND_UNSUBSCRIBE_RESPONSE,
    COMMAND_EVENT,
    COMMAND_UPDATE_EVENT,
    COMMAND_UPDATE_SUBSCRIBE_REQUEST,
    COMMAND_UPDATE_SUBSCRIBE_RESPONSE,
    COMMAND_GET_SUBSCRIPTION_REQUEST,
    COMMAND_GET_SUBSCRIPTION_RESPONSE,

    LIST_USER_REQUEST,
    LIST_USER_RESPONSE,

    LIST_NETWORK_REQUEST,
    LIST_NETWORK_RESPONSE,

    LIST_DEVICE_REQUEST,
    LIST_DEVICE_RESPONSE,

    LIST_DEVICE_CLASS_REQUEST,
    LIST_DEVICE_CLASS_RESPONSE
}
