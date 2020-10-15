/*
 * Heade File: set_helper.h
 * Last Update: 2020/10/15
 *
 * Copyright (C) Hydr10n@GitHub. All Rights Reserved.
 */

#pragma once

#include <set>

namespace Hydr10n {
	namespace std_container_helpers {
		struct set_helper final {
			template <class T1, class T2, class Compare = class std::set<T1>::key_compare, class Allocator = class std::set<T1>::allocator_type>
			static bool contains(const std::set<T1, Compare, Allocator>& container, const T2& item) { return container.find(item) != container.cend(); }

			template <class T1, class T2, class Compare = class std::set<T1>::key_compare, class Allocator = class std::set<T1>::allocator_type>
			static bool modify(std::set<T1, Compare, Allocator>& container, const T2& item, bool remove) {
				bool ret = contains(container, item) == remove;
				if (ret) {
					try {
						if (remove)
							container.erase(item);
						else
							container.insert(item);
					}
					catch (...) { ret = false; }
				}
				return ret;
			}
		};
	}
}