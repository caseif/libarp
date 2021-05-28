/*
 * This file is a part of libarp.
 * Copyright (c) 2020-2021, Max Roncace <mproncace@gmail.com>
 *
 * This software is made available under the MIT license. You should have
 * received a copy of the full license text with this software. If not, the
 * license text may be accessed at https://opensource.org/licenses/MIT.
 */

#pragma once

typedef void *DirHandle;

DirHandle open_directory(const char *path);

const char *read_directory(DirHandle dir);

void rewind_directory(DirHandle dir);

void close_directory(DirHandle dir);