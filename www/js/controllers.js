var httpPost = function(http, url, params) {
	return http({
		method: "POST",
		url: url,
		params: params,
	    headers: {'Content-Type': 'application/x-www-form-urlencoded'}
	});
};

var app = angular.module('tram', ['ngCookies', 'angularFileUpload', 'duScroll']);
app.controller("mainCtrl", function($scope, $http, $cookies) {
	$scope.sid = $cookies.get('sid') || false;
	$scope.storeSid = function(sid) {
		$scope.sid = sid;
		if (sid !== false) {
			$cookies.put('sid', $scope.sid);
		} else {
			$cookies.remove('sid');
		}
	}
	$scope.isAuthorized = function() {
		return $scope.sid !== false;
	}
	$scope.signinBy = function(way) {
		$scope.authWay = way;
	}
	$scope.logout = function() {
		if ($scope.sid === false) return;
		httpPost($http, 'user/logout', {"sid": $scope.sid}).success(function (response) { $scope.storeSid(false); });
	}
	$scope.signinBy("login");
	$scope.useRegistration = function() { return $scope.authWay == "registration"; }
	$scope.useLogin = function() { return $scope.authWay == "login"; }
});
app.controller('authCtrl', function($scope, $http) {
	var authHandler = function(response) {
		console.log(response);
		if ("sid" in response) {
			$scope.storeSid(response.sid);
		}
	}
	$scope.register = function (user) {
		httpPost($http, "user/register", user).success(authHandler);
	};
	$scope.login = function (user) {
		httpPost($http, "user/login", user).success(authHandler);
	};
});
app.controller('greeterCtrl', function($scope, $http) {
	$scope.$watch('sid', function (newSid, oldSid) {
		if (newSid !== false) {
			httpPost($http, 'user/info', {"sid": $scope.sid}).success(function(response) {
				console.log(response.user);
				if (response.status == "ok")
					$scope.user = response.user;
				else
					$scope.storeSid(false);
			});
		}
	});
});
app.controller('dataUploadCtrl', ['$scope', '$document', '$http', '$timeout', 'FileUploader', function($scope, $document, $http, $timeout, FileUploader) {
	var uploaderData = $scope.uploaderData = new FileUploader({
		url: 'uploads/data/add'
	});
	var uploaderControl = $scope.uploaderControl = new FileUploader({
		url: 'uploads/control/add'
	});
	var injectSid = function(item) { item.formData.push({"sid": $scope.sid});}
	uploaderData.onBeforeUploadItem = injectSid;
	uploaderControl.onBeforeUploadItem = injectSid;
	uploaderData.onSuccessItem = function(item, response, status, headers) {
		console.log(response);
		$scope.reloadDataList();
	};
	uploaderControl.onSuccessItem = function(item, response, status, headers) {
		console.log(response);
		$scope.reloadControlList();
	};
	$scope.reloadDataList = function() {
		httpPost($http, 'uploads/data/list', {"sid": $scope.sid}).success(function(response) {
			$scope.uploadedData = response.meta;
			console.log(response);
		});
	}
	$scope.reloadControlList = function() {
		httpPost($http, 'uploads/control/list', {"sid": $scope.sid}).success(function(response) {
			$scope.uploadedControl = response.meta;
			console.log(response);
		});
	}
	$scope.reloadUploadsList = function () {
		$scope.reloadDataList();
		$scope.reloadControlList();
	}
	$scope.selectData = function(id) {
		$scope.selectedDataId = id;
	}
	$scope.removeData = function(id) {
		httpPost($http, 'uploads/data/remove', {"sid": $scope.sid, "data_file_id": id}).success($scope.reloadDataList)
	}
	$scope.removeControl = function(id) {
		httpPost($http, 'uploads/control/remove', {"sid": $scope.sid, "control_file_id": id}).success($scope.reloadControlList)
	}
	$scope.selectControl = function(id) {
		$scope.selectedControlId = id;
	}
	$scope.selectedDataId = false;
	$scope.selectedControlId = false;
	$scope.$watch('sid', function(newSid, oldSid) {
		if (newSid !== false) {
			$scope.reloadUploadsList();
		}
	});
	$scope.task = {};
	$scope.readyToExecute = function() {
		return $scope.selectedDataId !== false && $scope.selectedControlId !== false;
	};
	$scope.pollTaskStatus = function() {
		httpPost($http, 'task/status', {"sid": $scope.sid, "task_id": $scope.task.id}).success(function(response) {
			console.log(response)
			$scope.task = response.task;
			if ($scope.task.Status == 'pending') {
				$timeout($scope.pollTaskStatus, 3000);
			} else {
				elem = angular.element(document.getElementById('output'));
				$document.scrollToElement(elem, 0, 2000);
			}
		})
	};
	$scope.execute = function () {
		httpPost($http, 'task/execute', { "sid": $scope.sid, "data_file_id": $scope.selectedDataId, "control_file_id": $scope.selectedControlId }).success(function (response) {
			if (response.status == 'ok') {
				$scope.task.id = response.task_id;
				$scope.pollTaskStatus();
				// $timeout($scope.pollTaskStatus, 3000);
			}
			// console.log(response);
			// console.log(response.control_meta);
			// console.log(response.data_meta);
		});
	};
}]);
