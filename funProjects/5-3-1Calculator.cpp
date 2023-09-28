#include <cstdio>
#include <iostream>

using namespace std;

double calculateWarm() {
	double max;

	double set1, set2, set3;
	cout << "Enter max: \n";
	cin >> max;
	set1 = max * .40;
	set2 = max * .50;
	set3 = max * .60;
	cout << set1 << "\n";  
	cout << set2 << "\n"; 
	cout << set3 << "\n";
	return 0;

}

double calculateWork() {
	double week, max, set1, set2, set3;
	cout << "What week are you on?\n";
	cin >> week;

	cout << "What is your max?\n";
	cin >> max;

	if (week == 1) {
		set1 = max * .65;
		set2 = max * .75;
		set3 = max * .85;
	}
	else if (week == 2) {
		set1 = max * .70;
		set2 = max * .80;
		set3 = max * .90;
	}
	else {
		set1 = max * .75;
		set2 = max * .85;
		set3 = max * .95;
	}
	cout << set1 << " " << set2 << " " << set3 << "\n";
	return 0;

}

double calculateMax() {
	double weight, reps, max;
	cout << "Enter weight:  \n";
	cin >> weight;

	cout << "Enter reps: \n";
	cin >> reps;

	max = weight * reps * .0333 + weight;

	cout << max << "\n";
	return max;
}


int main() {
	int option;
	cout << "Press 1 to calculate max.\nPress 2 calculate work.\nPress 3 to calculate warm up sets.\n ";
	cin >> option;

	if (option == 1) {
		calculateMax();
	}
	else if (option == 2) {
		calculateWork();
	}
	else {
		calculateWarm();
	}
	system("pause");
}
