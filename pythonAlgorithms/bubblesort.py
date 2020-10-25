def bubbleSort(list):
  lastElementIndex = len(list) - 1                  # variable to hold the length of the list - 1.  
  for passNo in range(lastElementIndex,0, -1):      # loop that starts the first number in list and goes to last number
      for i in range(passNo):                       # iterating of the number of passes
          if list[i] > list[i+1]:                   # comparing each number with it's adjacent number
              list[i],list[i+1] = list[i+1],list[i] # variable swapping to adjust the number's position if needed.
      return list

list = [25, 21, 22, 24, 23, 27, 26]
print(bubbleSort(list))

    
