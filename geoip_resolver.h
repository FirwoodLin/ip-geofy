#pragma once
#include <iostream>
#include <libmaxminddb/maxminddb.h>
#include <string>
#include <tuple>

#include "info_struct.h"

class GeoIPResolver {
public:
	MMDB_s mmdb;

	GeoIPResolver(const std::string& db_path) {
		int status = MMDB_open(db_path.c_str(), MMDB_MODE_MMAP, &mmdb);
		if (status != MMDB_SUCCESS) {
			std::cerr << "Failed to open MMDB: " << MMDB_strerror(status)
				<< std::endl;
		}
	}

	~GeoIPResolver() { MMDB_close(&mmdb); }

	std::tuple<std::string, std::string, std::string> lookup(const sockaddr* ip_address) {
		std::string country("未知");
		std::string province("未知");
		std::string city("未知");
		int gai_error, mmdb_error;
		MMDB_entry_data_s entry_data;
		MMDB_lookup_result_s result =
			MMDB_lookup_sockaddr(&mmdb, ip_address, &mmdb_error);
		if (mmdb_error != MMDB_SUCCESS) {
			std::cerr << "[ERROR]MMDB error" << std::endl;
			return { country, province, city };
		}

		if (result.found_entry) {
			// adopted from NyaTrace\ipdb.cpp
			MMDB_entry_data_s cityEntryData_cityName,
				cityEntryData_countryName,
				cityEntryData_provinceName // 免费版, 没有经纬度 radius
				;
			int getEntryDataStatus;
			// 城市名
			if ((getEntryDataStatus =
				MMDB_get_value(&result.entry, &cityEntryData_cityName, "city",
					"names", "zh-CN", NULL)) == MMDB_SUCCESS) {
				auto cityNameStr = strndup(cityEntryData_cityName.utf8_string,
					cityEntryData_cityName.data_size);
				city = std::string(cityNameStr);
				free(cityNameStr);
			}
			else if ((getEntryDataStatus = MMDB_get_value(
				&result.entry, &cityEntryData_cityName, "city", "names",
				"en", NULL)) == MMDB_SUCCESS) {
				// 城市名 获得英文名
				auto cityNameStr = strndup(cityEntryData_cityName.utf8_string,
					cityEntryData_cityName.data_size);
				city = std::string(cityNameStr);
				free(cityNameStr);
			}
			// 省份
			if ((getEntryDataStatus = MMDB_get_value(
				&result.entry, &cityEntryData_provinceName, "subdivisions", "0",
				"names", "zh-CN", NULL)) == MMDB_SUCCESS) {
				// 省份 尝试获取第一个行政区划的中文名
				if (cityEntryData_provinceName.has_data && cityEntryData_provinceName.type == MMDB_DATA_TYPE_UTF8_STRING) {
					auto provinceNameStr = strndup(cityEntryData_provinceName.utf8_string,
						cityEntryData_provinceName.data_size);
					province = std::string(provinceNameStr);
					free(provinceNameStr);
				}
				else {
					// 省份 unknown
					province = std::string("未知(数据格式错误)");
				}
			}
			else if ((getEntryDataStatus = MMDB_get_value(
				&result.entry, &cityEntryData_provinceName, "subdivisions", "0",
				"names", "en", NULL)) == MMDB_SUCCESS) {
				// 尝试获取第一个行政区划的英文名
				if (cityEntryData_provinceName.has_data && cityEntryData_provinceName.type == MMDB_DATA_TYPE_UTF8_STRING) {
					auto provinceNameStr = strndup(cityEntryData_provinceName.utf8_string,
						cityEntryData_provinceName.data_size);
					province = std::string(provinceNameStr);
					free(provinceNameStr);
				}
				else {
					province = std::string("未知(数据格式错误)");
				}
			}
			// 国家名
			if ((getEntryDataStatus = MMDB_get_value(
				&result.entry, &cityEntryData_countryName, "country", "names",
				"zh-CN", NULL)) == MMDB_SUCCESS) {
				// 获得中文名
				auto countryNameStr = strndup(cityEntryData_countryName.utf8_string,
					cityEntryData_countryName.data_size);
				country = std::string(countryNameStr);
				free(countryNameStr);
			}
			else if ((getEntryDataStatus = MMDB_get_value(
				&result.entry, &cityEntryData_countryName, "country",
				"names", "en", NULL)) == MMDB_SUCCESS) {
				// 获得英文名
				auto countryNameStr = strndup(cityEntryData_countryName.utf8_string,
					cityEntryData_countryName.data_size);
				country = std::string(countryNameStr);
				free(countryNameStr);
			}
			/*std::cerr << "[DEBUG]"
				<< "get country " << country << " provience " << province << " city " << city
				<< std::endl;*/
			return { country, province, city };
		}
		else {
			// 注意补充这里的返回语句
			//std::cerr << "[DEBUG] No location info successfully got" << std::endl;
			return { country, province, city };
		}
	}

private:
	char* strndup(const char* str, size_t n) {
		size_t len;
		char* copy;

		len = strnlen(str, n);
		if ((copy = (char*)malloc(len + 1)) == NULL)
			return (NULL);
		memcpy(copy, str, len);
		copy[len] = '\0';
		return (copy);
	}
};
