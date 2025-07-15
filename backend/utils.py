
import time
from django.http import JsonResponse
from .models import Task

def poll_task_completion(task_ids):
    """
    Poll for task completion with optimized intervals.
    
    Args:
        task_ids (list): List of task IDs to monitor
        
    Returns:
        tuple: (completed_tasks, failed_tasks, pending_tasks, status_code)
    """
    max_wait_time = 15  # Maximum wait time in seconds
    initial_interval = 0.05  # Start with 50ms
    backoff_factor = 1.2  # Smaller backoff factor
    max_interval = 0.5  # Maximum interval of 500ms
    
    current_interval = initial_interval
    start_time = time.time()
    completed_tasks = []
    failed_tasks = []

    while (time.time() - start_time) < max_wait_time:
        # Batch query for all tasks at once and force evaluation
        all_tasks = list(Task.objects.filter(id__in=task_ids).values('id', 'status'))
        
        # Reset lists for each iteration
        completed_tasks = []
        failed_tasks = []
        
        for task in all_tasks:
            # Explicitly compare with Task model status constants
            if task['status'] == 'COMPLETED':
                completed_tasks.append(task['id'])
            elif task['status'] == 'FAILED':
                failed_tasks.append(task['id'])
        
        # If all tasks are done, break immediately
        if len(completed_tasks) + len(failed_tasks) == len(task_ids):
            break

        # If any tasks completed, check very frequently
        if completed_tasks or failed_tasks:
            current_interval = initial_interval
        else:
            # Gentle increase in interval
            current_interval = min(current_interval * backoff_factor, max_interval)

        time.sleep(current_interval)

    # Calculate pending tasks after the loop
    pending_tasks = [task_id for task_id in task_ids if task_id not in completed_tasks + failed_tasks]
    status_code = 202 if pending_tasks else 200

    return completed_tasks, failed_tasks, pending_tasks, status_code

# Example usage in your view:
def get_task_response(completed_tasks, failed_tasks, pending_tasks, status_code):
    """
    Helper function to generate consistent task response
    """
    if pending_tasks:
        return JsonResponse({
            "message": "Some tasks are still processing.",
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "pending_tasks": pending_tasks,
            "total_tasks": len(completed_tasks) + len(failed_tasks) + len(pending_tasks),
            "completed_count": len(completed_tasks),
            "failed_count": len(failed_tasks),
            "pending_count": len(pending_tasks)
        }, status=status_code)
    
    return JsonResponse({
        "message": "All tasks processed.",
        "completed_tasks": completed_tasks,
        "failed_tasks": failed_tasks,
        "total_tasks": len(completed_tasks) + len(failed_tasks),
        "completed_count": len(completed_tasks),
        "failed_count": len(failed_tasks)
    }, status=status_code)