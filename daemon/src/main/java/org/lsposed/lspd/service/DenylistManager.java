/*
 * This file is part of ReLSPosed.
 *
 * ReLSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ReLSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ReLSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2023 The PerformanC Organization Contributors
 */
// ------------------------------------------------------------------------------------------------------------------------------------------------
/* INFO: Code below contains parts of the code of the ReZygisk's Daemon. It is protected by its AGPL 3.0.0 license by The PerformanC Organization.
           See https://github.com/PerformanC/ReZygisk repository for more details. */
// ------------------------------------------------------------------------------------------------------------------------------------------------

package org.lsposed.lspd.service;

public class DenylistManager {
    native static boolean isInDenylist(String processName);
}
