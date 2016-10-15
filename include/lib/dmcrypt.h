/*
 * Copyright 2016, The EFIDroid Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef _LIB_DMCRYPT_H_
#define _LIB_DMCRYPT_H_

int cryptfs_setup_ext_volume(const char *label, const char *real_blkdev,
                             const unsigned char *key, int keysize, char *out_crypto_blkdev);
int cryptfs_revert_ext_volume(const char *label);

#endif
